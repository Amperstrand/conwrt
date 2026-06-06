# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Post-flash configuration and SSH helper functions.

Extracted from conwrt/__init__.py for maintainability. Re-exported via __init__.py
so that `conwrt.<name>` and `@patch("conwrt.<name>")` continue to work.
"""

import argparse
import base64
import importlib
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from ssh_utils import DROPBEAR_AUTH_KEYS_PATH, run_ssh, ssh_cmd
from model_loader import load_model
from flash.context import DEFAULT_IP, log, poll_until
from sticker_creds import dump_and_extract_config2, apply_credentials_to_openwrt
from platform_utils import configure_interface_ip, remove_interface_ip, detect_platform
from profile import apply_plan, apply_ubus, build_plan
from inventory import append_to_inventory as _append_to_inventory

from conwrt.monitors import check_ssh
from conwrt.flash_utils import _wait_for_sysupgrade_reboot
from conwrt.device_inventory import auto_detect_interface
from conwrt.infrastructure import _generate_random_password

_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint


def _apply_profile_post_flash(
    ip: str,
    ssh_key: str = "",
    cfg: object = None,
    model_id: str = "",
    interface: str = "",
    old_client_ip: str = "",
    *,
    password: Optional[str] = None,
    wan_ssh: Optional[bool] = None,
    ssh_key_path: Optional[str] = None,
    dry_run: bool = False,
    hostname: str = "",
    wifi_disable: bool = False,
    lan_ip_mode: str = "",
    hostname_pattern: str = "",
    transport: str = "ssh",
    ubus_user: str = "root",
    ubus_password: str = "",
) -> str:
    """Apply config.toml profile via unified plan (WiFi, use cases, LAN IP)."""
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ip

    model_caps: list[str] = []
    if model_id:
        try:
            model = load_model(model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError:
            pass

    effective_wan_ssh = cfg.wan_ssh if wan_ssh is None else wan_ssh
    plan = build_plan(
        cfg,
        mode="preview" if dry_run else "post_install",
        model_capabilities=model_caps,
        ssh_key_path=ssh_key_path,
        password=password,
        wan_ssh=effective_wan_ssh,
        hostname=hostname,
        wifi_disable=wifi_disable,
        lan_ip_mode=lan_ip_mode,
        hostname_pattern=hostname_pattern,
        model_id=model_id,
    )
    if not dry_run:
        log(f"Applying profile via {transport}...")
    if transport == "ubus":
        ip = apply_ubus(
            plan, ip, username=ubus_user, password=ubus_password,
            dry_run=dry_run, log=log,
        )
    else:
        ip = apply_plan(plan, ip, ssh_key=ssh_key, dry_run=dry_run, log=log)

    # --- Post-apply: hostname read-back (SSH only) ---
    if transport == "ssh" and not dry_run:
        from profile.plan import StepKind as _SK
        has_hostname_step = any(s.kind == _SK.HOSTNAME and s.include_in_post_install for s in plan.steps)
        if has_hostname_step:
            r_host = run_ssh(ip, "cat /proc/sys/kernel/hostname", key=ssh_key, timeout=10)
            if r_host.returncode == 0 and r_host.stdout.strip():
                resolved_hostname = r_host.stdout.strip()
                log(f"  Hostname resolved: {resolved_hostname}")

    # --- Post-apply: static LAN IP (SSH only) ---
    if transport == "ssh" and not dry_run and cfg.lan_ip and interface:
        new_ip = _apply_lan_ip_post_flash(
            ip, ssh_key=ssh_key, cfg=cfg,
            interface=interface, old_client_ip=old_client_ip,
        )
        if new_ip:
            ip = new_ip

    # --- Post-apply: MAC-hash LAN IP (SSH only) ---
    from profile.plan import StepKind
    from mac_hash import mac_to_lan_ip
    for step in plan.steps:
        if step.kind != StepKind.LAN_IP_MAC_HASH:
            continue
        if not step.include_in_post_install:
            continue
        if dry_run:
            log(f"  {step.label} (dry run)")
            continue
        if transport != "ssh":
            log(f"  ⚠ {step.label}: MAC-hash LAN IP requires SSH — skipped for ubus transport")
            continue

        script = (step.configure_script or "").replace(" && ", "; ")
        if not script:
            continue
        subnet = (step.wifi_params or {}).get("lan_subnet", "")
        if not subnet:
            log(f"  ⚠ {step.label}: no subnet configured — skipping")
            continue

        # Read MAC before changing IP so we can predict the new IP.
        # br-lan has the stable factory MAC; eth0 is the CPU port (unstable on DSA).
        r_mac = run_ssh(ip, "cat /sys/class/net/br-lan/address 2>/dev/null", key=ssh_key)
        if r_mac.returncode != 0 or not r_mac.stdout.strip():
            r_mac = run_ssh(ip, "cat /sys/class/net/eth0/address 2>/dev/null", key=ssh_key)
        if r_mac.returncode != 0 or not r_mac.stdout.strip():
            log(f"  ⚠ {step.label}: could not read MAC — skipping")
            continue
        device_mac = r_mac.stdout.strip()
        expected_ip = mac_to_lan_ip(device_mac, subnet)
        log(f"  {step.label}... (mac={device_mac}, expected={expected_ip})")

        r = run_ssh(ip, script, key=ssh_key)
        if r.returncode == 0:
            log(f"  ✓ {step.label} — IP set to {expected_ip}, rebooting...")
            run_ssh(ip, "sync; sync; reboot", key=ssh_key, timeout=5)
            time.sleep(30)

            # Set up local interface on new subnet before reconnecting
            if interface:
                new_client_ip = _client_ip_for_subnet(expected_ip)
                if old_client_ip:
                    remove_interface_ip(interface, old_client_ip, "24")
                configure_interface_ip(interface, new_client_ip, "24")
                log(f"  Local interface {interface} configured with {new_client_ip}/24")

            # Wait for SSH on the new (known) IP
            for attempt in range(12):
                if check_ssh(expected_ip):
                    log(f"  ✓ Reconnected at {expected_ip}")
                    ip = expected_ip
                    break
                if attempt == 0:
                    log(f"  Waiting for device at {expected_ip}...")
                time.sleep(5)
            else:
                log(f"  ⚠ Device did not come back at {expected_ip} within 60s")
                log(f"  The IP was changed. Try: sudo ifconfig {interface} inet {_client_ip_for_subnet(expected_ip)}/24 alias")
        else:
            log(f"  ⚠ {step.label}: failed to set MAC-hash IP")

    return ip


def _apply_sticker_credentials_post_flash(
    ip: str, ssh_key: str = "", model_id: str = "", cfg: object = None,
) -> None:
    """Restore factory sticker WiFi credentials after flashing.

    Only activates when the model has a ``sticker_credentials`` section in
    its model JSON AND the user hasn't configured an explicit WiFi AP in
    config.toml (sticker creds are the fallback/default).
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return

    if cfg.wifi_ap:
        return

    if not model_id:
        return
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        return
    if "sticker_credentials" not in model:
        return

    log("Restoring factory sticker WiFi credentials...")
    key = ssh_key or None
    try:
        data = dump_and_extract_config2(ip, key=key)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: dump failed — {exc}")
        return

    wifi = data.get("wifi", {})
    macs = data.get("macs", {})
    ssid_24g = wifi.get("ssid_24g", "")
    ssid_5g = wifi.get("ssid_5g", "")
    log(f"  Extracted: 2.4G SSID={ssid_24g or '(none)'}, "
        f"5G SSID={ssid_5g or '(none)'}")
    if macs.get("factory_mac"):
        log(f"  Factory MAC: {macs['factory_mac']}")

    try:
        apply_credentials_to_openwrt(ip, wifi, key=key, model_id=model_id)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: apply failed — {exc}")
        return

    log("  ✓ sticker credentials applied")


def _register_wireguard_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
) -> str:
    """Read the auto-generated WireGuard public key from the router and
    register it with the VPN server.

    Returns the public key string, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.wireguard or not cfg.wireguard.registration_server:
        return ""

    server = cfg.wireguard.registration_server
    wg_if = cfg.wireguard.wg_interface
    key = ssh_key or None

    # Try to read the public key directly (interface may already be up)
    r = subprocess.run(
        ssh_cmd(ip, "wg show wg0 public-key 2>/dev/null", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    pub_key = r.stdout.strip()

    # If interface isn't up yet, derive from private key without leaking it
    # to the process table (pipe via stdin, not command-line args)
    if not pub_key or len(pub_key) < 40:
        r1 = subprocess.run(
            ssh_cmd(ip, "uci -q get network.wg0.private_key", key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        priv_key = r1.stdout.strip()
        if not priv_key or priv_key == "generate":
            log("  WG: no private key found on router (WireGuard not configured)")
            return ""

        # Pipe private key through stdin to avoid exposing it in ps/process args
        r2 = subprocess.run(
            ssh_cmd(ip, "wg pubkey", key=key, connect_timeout=10),
            input=priv_key, capture_output=True, text=True, timeout=15, check=False,
        )
        pub_key = r2.stdout.strip()
        if not pub_key or len(pub_key) < 40:
            log(f"  ⚠ WG: could not derive public key (got {len(pub_key)} chars)")
            return ""

    log(f"  WG: public key = {pub_key}")

    # Read the tunnel address from the router
    r3 = subprocess.run(
        ssh_cmd(ip, "uci -q get network.wg0.addresses", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    address = r3.stdout.strip()
    if not address:
        log("  ⚠ WG: no tunnel address configured on router — skipping registration")
        return ""

    # Register the peer with the VPN server
    log(f"  WG: registering peer {address} with {server}...")
    reg_cmd = f"wg set {wg_if} peer {pub_key} allowed-ips {address}"
    r4 = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, reg_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if r4.returncode == 0:
        log(f"  ✓ WG: peer registered with {server}")
    else:
        log(f"  ⚠ WG: registration failed — {r4.stderr.strip()[:200]}")

    addr_host = address.split("/")[0]
    persist_cmd = (
        f"grep -q '{pub_key}' /etc/wireguard/{wg_if}.conf 2>/dev/null || "
        f"printf '\\n[Peer]\\nPublicKey = {pub_key}\\nAllowedIPs = {addr_host}/32\\n' "
        f">> /etc/wireguard/{wg_if}.conf"
    )
    r5 = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, persist_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if r5.returncode != 0:
        log(f"  ⚠ WG: peer persistence failed (rc={r5.returncode}) — peer may not survive reboot")

    return pub_key


def _deploy_tollgate_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
) -> None:
    """Deploy tollgate ipk to the router if the tollgate use case is enabled."""
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return

    tollgate_cfg = None
    for uc in cfg.use_cases:
        if uc.name == "tollgate":
            tollgate_cfg = uc.params
            break
    if tollgate_cfg is None:
        return

    from use_cases.tollgate import deploy_tollgate_post_flash
    deploy_tollgate_post_flash(
        ip,
        ssh_key=ssh_key,
        arch=tollgate_cfg.get("arch", ""),
        channel=tollgate_cfg.get("channel", "stable"),
        version=tollgate_cfg.get("version", "latest"),
        source=tollgate_cfg.get("source", "auto"),
        log=log,
    )


def _client_ip_for_subnet(router_ip: str) -> str:
    """Derive a client IP on the same /24 subnet as router_ip.

    Takes the first three octets from router_ip and uses .254 as the client.
    """
    octets = router_ip.split(".")
    if len(octets) != 4:
        return ""
    return f"{octets[0]}.{octets[1]}.{octets[2]}.254"


def _interface_exists(interface: str) -> bool:
    """Check if a network interface exists on this system."""
    r = subprocess.run(
        ["ifconfig", interface], capture_output=True, text=True, check=False,
    )
    return r.returncode == 0


def _apply_lan_ip_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
    interface: str = "", old_client_ip: str = "",
) -> str:
    """Change the router's LAN IP and reconnect on the new subnet.

    This MUST be the last post-flash step — the network restart will drop SSH.
    After changing the router's LAN IP:
      1. Remove old client IP alias from the interface
      2. Add new client IP alias on the new subnet
      3. Wait for the router to come back on the new IP
      4. Verify SSH on the new IP

    Returns the new router IP, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.lan_ip:
        return ""
    if not interface:
        log("  ⚠ LAN IP: no interface — skipping IP change")
        return ""

    new_ip = cfg.lan_ip
    if new_ip == ip:
        return new_ip

    new_client_ip = _client_ip_for_subnet(new_ip)
    if not new_client_ip:
        log(f"  ⚠ LAN IP: invalid target IP '{new_ip}'")
        return ""

    log(f"  Changing LAN IP from {ip} to {new_ip}...")
    key = ssh_key or None

    uci_commands = " && ".join([
        f"uci set network.lan.ipaddr='{new_ip}'",
        "uci commit network",
        "(/etc/init.d/network reload >/dev/null 2>&1) &",
        "exit 0",
    ])
    try:
        r = subprocess.run(
            ssh_cmd(ip, uci_commands, key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        log(f"  LAN IP change command sent (rc={r.returncode})")
    except subprocess.TimeoutExpired:
        log("  LAN IP change: SSH session ended (expected — network restarting)")

    time.sleep(5)

    # Interface may have dropped during router network restart (USB adapter re-enumeration)
    if not _interface_exists(interface):
        log(f"  Interface {interface} dropped during network restart. Waiting for it to come back...")
        if poll_until(lambda: _interface_exists(interface), timeout=30, interval=1):
            log(f"  Interface {interface} reappeared.")
        else:
            new_iface = auto_detect_interface()
            if new_iface and new_iface != interface:
                log(f"  Interface re-enumerated as {new_iface}")
                interface = new_iface
            else:
                log(f"  ⚠ LAN IP: interface {interface} disappeared and did not come back")
                log(f"  The router IP was changed to {new_ip}. Reconnect manually with: "
                    f"sudo ifconfig <interface> inet {new_client_ip}/24 alias")
                return ""

    if old_client_ip:
        remove_interface_ip(interface, old_client_ip, "24")

    plat = detect_platform()
    if plat == "darwin":
        subprocess.run(["sudo", "arp", "-d", ip], capture_output=True, check=False)
        subprocess.run(["sudo", "arp", "-d", new_ip], capture_output=True, check=False)
    else:
        subprocess.run(["ip", "neigh", "flush", "to", ip], capture_output=True, check=False)
        subprocess.run(["ip", "neigh", "flush", "to", new_ip], capture_output=True, check=False)

    configure_interface_ip(interface, new_client_ip, "24")

    log(f"  Waiting for router at {new_ip} (client IP {new_client_ip})...")
    if _wait_for_sysupgrade_reboot(new_ip, timeout=120):
        log(f"  ✓ LAN IP changed to {new_ip}")
        return new_ip
    else:
        log(f"  ⚠ LAN IP: router did not come back at {new_ip}")
        return ""


def verify_router(ip: str = DEFAULT_IP, wan_ssh_expected: bool = False,
                  mgmt_wifi_expected: bool = False) -> list[tuple[str, str]]:
    log("Verifying router state...")
    checks: list[tuple[str, str]] = []
    try:
        r = subprocess.run(
            ssh_cmd(ip,
                    "echo hostname=$(cat /proc/sys/kernel/hostname); "
                    "echo board=$(cat /etc/board.json | jsonfilter -e '@.model.id' 2>/dev/null || echo unknown); "
                    "echo kernel=$(uname -r); "
                    f"echo sshkey_count=$(wc -l < {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo 0); "
                    f"echo sshkey_size=$(wc -c < {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo 0); "
                    "echo wan_ssh=$(uci show firewall 2>/dev/null | grep Allow-SSH-WAN | wc -l); "
                    "echo uci_defaults=$(ls /etc/uci-defaults/ 2>/dev/null | wc -l); "
                    "echo mac_brlan=$(cat /sys/class/net/br-lan/address 2>/dev/null || echo ''); "
                    "echo 'mac_all='$(for f in /sys/class/net/*/address; do printf '%s=%s ' $(basename $(dirname $f)) $(cat $f 2>/dev/null); done); "
                    "echo mgmt_wifi=$(uci -q get network.mgmt.ipaddr || echo ''); "
                    "echo mgmt_ssid=$(uci -q get wireless.@wifi-iface[0].ssid || echo ''); "
                    "echo mgmt_radio=$(uci -q get wireless.radio0.disabled || echo ''); "
                    "echo nmap_ok=$(which nmap >/dev/null 2>&1 && echo yes || echo no); "
                    "echo ping_ok=$(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo yes || echo no)",
                    connect_timeout=5),
            capture_output=True, text=True, timeout=20, check=False,
        )
        for line in r.stdout.strip().split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                checks.append((key, val))
                log(f"  verify: {key}: {val}")

        d = dict(checks)

        uci_defaults = d.get("uci_defaults", "?")
        if uci_defaults == "0":
            log("  ✓ uci-defaults: all consumed (first boot complete)")
        else:
            log(f"  ⚠ uci-defaults: {uci_defaults} remaining")

        sshkey_count = d.get("sshkey_count", "0")
        if int(sshkey_count or 0) > 0:
            log(f"  ✓ SSH keys: {sshkey_count} authorized")
        else:
            log("  ⚠ SSH keys: none found")

        if wan_ssh_expected:
            wan_ssh = d.get("wan_ssh", "0")
            if int(wan_ssh or 0) > 0:
                log("  ✓ WAN SSH: firewall rule present")
            else:
                log("  ⚠ WAN SSH: no firewall rule found")

        if mgmt_wifi_expected:
            mgmt_ip = d.get("mgmt_wifi", "")
            mgmt_ssid = d.get("mgmt_ssid", "")
            if mgmt_ip:
                log(f"  ✓ mgmt WiFi: network configured ({mgmt_ip})")
            else:
                log("  ⚠ mgmt WiFi: network not configured")
            if mgmt_ssid.startswith("MGMT-"):
                log(f"  ✓ mgmt WiFi: SSID={mgmt_ssid}")
            else:
                log(f"  ⚠ mgmt WiFi: unexpected SSID '{mgmt_ssid}'")

        ping_ok = d.get("ping_ok", "no")
        if ping_ok == "yes":
            log("  ✓ network: connectivity confirmed (ping 8.8.8.8)")
        else:
            log("  ⚠ network: no connectivity")

        nmap_ok = d.get("nmap_ok", "no")
        if nmap_ok == "yes":
            log("  ✓ extra package: nmap installed")

    except Exception as e:
        log(f"Verification failed: {e}")
    return checks


def _cfg_install_ssh_key(ip: str, key_path: str, auth_key: str = "", ssh_key: str = "") -> bool:
    """Idempotent SSH key installation. Skips if key already present.

    key_path: path to public key file (for reading the key to install).
    auth_key: private key path used for SSH authentication.
    ssh_key: public key text (alternative to key_path).

    IMPORTANT: This MUST be called BEFORE _cfg_set_password. OpenWrt allows
    passwordless root login by default — once a password is set, passwordless
    login stops. If SSH keys aren't installed first, you lose remote access.
    """
    pub_key = ""
    if ssh_key and ssh_key.startswith("ssh-"):
        pub_key = ssh_key.split("\n")[0].strip()
        parts = pub_key.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    elif key_path:
        from pathlib import Path as _P
        raw = _P(key_path).expanduser().read_text().strip()
        parts = raw.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    if not pub_key:
        log("  ⚠ SSH key: no key provided — skipping")
        return False

    log("  SSH key: checking current state...")
    r = run_ssh(ip, f"cat {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo ''", key=auth_key)
    current_keys = r.stdout.strip()
    if pub_key in current_keys:
        log("  ✓ SSH key: already installed")
        return True

    log("  SSH key: installing...")
    needs_create = "No such file" in r.stderr or not current_keys
    op = ">" if needs_create or not current_keys else ">>"
    escaped = pub_key.replace("'", "'\\''")
    auth_dir = DROPBEAR_AUTH_KEYS_PATH.rsplit('/', 1)[0]
    install_r = run_ssh(
        ip,
        f"mkdir -p {auth_dir} && echo '{escaped}' {op} {DROPBEAR_AUTH_KEYS_PATH} && chmod 600 {DROPBEAR_AUTH_KEYS_PATH}",
        key=auth_key,
    )
    if install_r.returncode != 0:
        log(f"  ⚠ SSH key: install failed (rc={install_r.returncode})")
        return False

    verify_r = run_ssh(ip, f"cat {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo ''", key=auth_key)
    if pub_key in verify_r.stdout:
        log("  ✓ SSH key: installed and verified")
        return True
    log("  ⚠ SSH key: verification failed")
    return False


def _cfg_set_password(ip: str, password: str, ssh_key: str = "") -> bool:
    """Set root password. Always runs (idempotent — setting same password is fine)."""
    if not password:
        log("  Password: no password provided — skipping")
        return False

    log("  Password: setting...")
    pw_b64 = base64.b64encode(password.encode()).decode()
    r = run_ssh(
        ip,
        f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" \"$(echo '{pw_b64}' | base64 -d)\" | passwd root",
        key=ssh_key,
    )
    if r.returncode != 0:
        log(f"  ⚠ Password: failed (rc={r.returncode})")
        return False
    log("  ✓ Password: set")
    return True


def _record_configure_inventory(
    ip: str,
    password: str = "",
    serial: str = "",
    model_id: str = "",
    ssh_key_path: str = "",
    wan_ssh: bool = False,
) -> None:
    """Fingerprint router and append configuration results to inventory.jsonl.

    Called from cmd_configure after successful configuration. Records the
    generated password, serial (if provided), MAC addresses, and device
    identity so we have a permanent record of what was configured.
    """
    fp = fingerprint_router(ip)
    if not fp:
        log("  ⚠ inventory: could not fingerprint router — skipping inventory write")
        return

    ident = fp.get("identity", {})
    fw = fp.get("firmware", {})
    net = fp.get("network", {})
    sec = fp.get("security", {})
    macs = net.get("macs", {})

    board = ident.get("board", "")
    fp_path = save_fingerprint(fp, board_id=board)

    openwrt_target = ""
    if model_id:
        try:
            model = load_model(model_id)
            openwrt_target = model.get("openwrt", {}).get("target", "")
        except FileNotFoundError:
            pass

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "configure",
        "device_serial": serial or ident.get("serial", ""),
        "model": ident.get("model", ""),
        "model_id": model_id,
        "vendor": fw.get("DISTRIB_ID", "").strip("'\"") or ident.get("vendor", ""),
        "firmware_version": fw.get("version", "").strip("'\""),
        "openwrt_target": openwrt_target,
        "hostname": ident.get("hostname", ""),
        "board": board,
        "kernel": fw.get("kernel", ""),
        "mac_addresses": {k: v for k, v in macs.items() if v and k != "lo"},
        "ssh_key_fingerprint": sec.get("ssh_fingerprint", ""),
        "ssh_key_count": sec.get("ssh_key_count", 0),
        "wan_ssh_rules": sec.get("wan_ssh_rules", 0),
        "password_set": bool(password),
        "wan_ssh_enabled": wan_ssh,
        "flashed_by": os.environ.get("USER", ""),
        "fingerprint_file": str(fp_path) if fp_path else "",
        "notes": "Configured via conwrt configure",
    }

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        _append_to_inventory(entry, str(inventory_path))
        log(f"  ✓ inventory: entry appended to {inventory_path}")
        if password:
            log(f"  ✓ inventory: password recorded for serial={serial or '(unknown)'}")
    except Exception as e:
        log(f"  ⚠ inventory: failed to write — {e}")


def _resolve_configure_options(
    args: argparse.Namespace, cfg: object,
) -> tuple[str, str, str, str, bool]:
    """Resolve effective configure options (CLI overrides config.toml).

    Returns (password, ssh_private_key_path, ssh_pub_path, ssh_key_text, wan_ssh).
    Password is empty when --no-password or when not configured.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return "", "", "", "", False

    ssh_key_path = args.ssh_key or cfg.ssh_private_key_path or ""
    ssh_pub_path = cfg.ssh_public_key_path
    ssh_key_text = cfg.ssh_public_key_text
    if args.ssh_key:
        from pathlib import Path as _P
        p = _P(args.ssh_key).expanduser()
        if p.is_file() and p.suffix == ".pub":
            ssh_pub_path = str(p)

    if args.no_password:
        password = ""
    elif args.password:
        password = args.password
    elif cfg.password_is_random:
        password = _generate_random_password()
    else:
        password = cfg.password_literal or ""

    wan_ssh = cfg.wan_ssh
    if args.wan_ssh:
        wan_ssh = True

    return password, ssh_key_path, ssh_pub_path, ssh_key_text, wan_ssh
