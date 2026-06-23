"""fingerprint command — identify the unknown device via SSH ProxyJump.

SSHes to the target device through the field router (ProxyJump) and collects
identity, network, and service info. This is the Mac-driven discovery path:
the Mac does the work, the field router is just the network bridge.

Unlike discover (which probes from the field router), fingerprint gets full
SSH access to the target — model, packages, network config, the works.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from fieldlab.transport import Host, run_remote
from fieldlab.rundir import FieldLabRun


_FINGERPRINT_SCRIPT = """\
echo '===BOARD==='; ubus call system board 2>/dev/null
echo '===RELEASE==='; cat /etc/openwrt_release 2>/dev/null
echo '===MODEL==='; cat /tmp/sysinfo/model 2>/dev/null
echo '===BOARD_NAME==='; cat /tmp/sysinfo/board_name 2>/dev/null
echo '===HOSTNAME==='; cat /proc/sys/kernel/hostname 2>/dev/null
echo '===KERNEL==='; uname -rms 2>/dev/null
echo '===MAC_ALL==='; for f in /sys/class/net/*/address; do echo "$(basename $(dirname $f))=$(cat $f)"; done 2>/dev/null
echo '===IP_ADDR==='; ip -br addr 2>/dev/null
echo '===IP_ROUTE==='; ip route 2>/dev/null
echo '===PACKAGES==='; opkg list-installed 2>/dev/null | wc -l
echo '===SSH_KEYS==='; cat /etc/dropbear/authorized_keys 2>/dev/null | wc -l
echo '===FIREWALL_RULES==='; uci show firewall 2>/dev/null | grep -c 'rule'
echo '===TOOLS==='; for t in tcpdump curl wget nc nmap; do printf '%s=' "$t"; which "$t" 2>/dev/null || echo missing; done
echo '===NETWORK_UCI==='; uci show network 2>/dev/null
echo '===WIRELESS_UCI==='; uci show wireless 2>/dev/null | head -20
"""


def _parse_sections(raw: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = None
    for line in raw.split("\n"):
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = line[3:-3]
            sections[current] = ""
        elif current is not None:
            sections[current] += line + "\n"
    return {k: v.strip() for k, v in sections.items()}


def cmd_fingerprint(args: argparse.Namespace, host: Host) -> int:
    """Fingerprint the target device through the field router via ProxyJump."""
    target_ip = args.target
    jump = str(host)

    print(f"[+] Fingerprinting {target_ip} via {jump}...", file=sys.stderr)

    target_host = Host(ip=target_ip, user="root")
    result = run_remote(target_host, _FINGERPRINT_SCRIPT, timeout=30, jump=jump)

    if result.returncode != 0:
        print(f"[!] SSH to {target_ip} failed: {result.stderr.strip()}", file=sys.stderr)
        return 1

    sections = _parse_sections(result.stdout)

    fingerprint = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_ip": target_ip,
        "via_jump": jump,
        "board": sections.get("BOARD", ""),
        "release": sections.get("RELEASE", ""),
        "model": sections.get("MODEL", ""),
        "board_name": sections.get("BOARD_NAME", ""),
        "hostname": sections.get("HOSTNAME", ""),
        "kernel": sections.get("KERNEL", ""),
        "macs": sections.get("MAC_ALL", ""),
        "ip_addresses": sections.get("IP_ADDR", ""),
        "routes": sections.get("IP_ROUTE", ""),
        "package_count": sections.get("PACKAGES", ""),
        "ssh_key_count": sections.get("SSH_KEYS", ""),
        "firewall_rule_count": sections.get("FIREWALL_RULES", ""),
        "tools": sections.get("TOOLS", ""),
        "network_uci": sections.get("NETWORK_UCI", ""),
        "wireless_uci": sections.get("WIRELESS_UCI", ""),
    }

    output = json.dumps(fingerprint, indent=2)

    session = args.session
    run = FieldLabRun(session) if session else FieldLabRun.create()
    run.inspect_dir.mkdir(parents=True, exist_ok=True)
    fp_path = run.inspect_dir / f"target-{target_ip.replace('.', '-')}.json"
    fp_path.write_text(output + "\n")
    run.record_command("fingerprint", target=target_ip, via_jump=jump)

    print(f"[+] Model: {fingerprint['model']}", file=sys.stderr)
    print(f"[+] Board: {fingerprint['board_name']}", file=sys.stderr)
    print(f"[+] OpenWrt: {fingerprint['release'].split(chr(10))[3] if 'DISTRIB_RELEASE' in fingerprint['release'] else '?'}", file=sys.stderr)
    print(f"[+] Hostname: {fingerprint['hostname']}", file=sys.stderr)
    print(f"[+] Written to {fp_path}", file=sys.stderr)

    sys.stdout.write(output + "\n")
    return 0
