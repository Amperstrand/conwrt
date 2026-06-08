from __future__ import annotations
import sys
import subprocess
import argparse
from pathlib import Path

_CONWRT_DIR = str(Path(__file__).resolve().parent)
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)

from conwrt.flash_utils import _detect_ssh_key_path
from config import load_config as _load_config
from profile.wifi import build_mgmt_wifi_script
from ssh_utils import ssh_cmd


def cmd_setup_mgmt_wifi(args: argparse.Namespace) -> int:
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    verify_cmd = " && ".join([
        "uci -q get network.mgmt.ipaddr | grep -qx '172.16.0.1'",
        "uci -q get dhcp.mgmt.interface | grep -qx 'mgmt'",
        "uci -q show firewall | grep -q \"\\.name='mgmt'\"",
        "uci -q show wireless | grep -q \"\\.network='mgmt'\"",
    ])
    verify_result = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result.returncode == 0:
        print(f"Management WiFi already configured on {args.ip}")
        return 0

    cfg = _load_config()
    script = build_mgmt_wifi_script(txpower=cfg.mgmt_wifi_txpower)
    ssh_command = ssh_cmd(args.ip, "sh -s", key=ssh_key, connect_timeout=10)

    try:
        result = subprocess.run(
            ssh_command,
            input=script,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: Timed out configuring management WiFi on {args.ip}.", file=sys.stderr)
        return 1
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"ERROR: Failed to run setup script over SSH: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        return result.returncode or 1

    verify_result2 = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result2.returncode != 0:
        if result.stdout.strip():
            print(result.stdout.strip())
        if verify_result2.stderr.strip():
            print(verify_result2.stderr.strip(), file=sys.stderr)
        print("ERROR: Management WiFi verification failed.", file=sys.stderr)
        return 1

    if result.stdout.strip():
        print(result.stdout.strip())
    print(f"Management WiFi configured on {args.ip}")
    return 0
