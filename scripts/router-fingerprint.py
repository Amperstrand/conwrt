#!/usr/bin/env python3
"""
Router Fingerprint Script
Connects to an OpenWrt router via SSH and collects comprehensive identifying information.
"""

import subprocess
import json
import sys
import os
import socket
import argparse
import re
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ssh_utils import run_ssh

def get_default_gateway(interface: Optional[str] = None) -> Optional[str]:
    """Get default gateway IP address."""
    import platform
    try:
        if platform.system() == "Linux" or os.path.exists('/sbin/ip'):
            cmd = ['ip', 'route', 'show', 'default']
            if interface:
                cmd[2:2] = ['dev', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'via' in line:
                        parts = line.split()
                        if 'via' in parts:
                            return parts[parts.index('via') + 1]
        elif platform.system() == "Darwin":
            cmd = ['route', '-n', 'get', 'default']
            if interface:
                cmd.extend(['-ifscope', interface])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'gateway' in line:
                        parts = line.split()
                        if 'gateway' in parts:
                            return parts[parts.index('gateway') + 1]
    except Exception:
        pass
    return None

def parse_ssh_output(output: str) -> Dict[str, str]:
    """Parse SSH output separated by markers."""
    sections = {}
    current_section = None

    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('===') and line.endswith('==='):
            current_section = line[3:-3]
            sections[current_section] = []
        elif current_section and line:
            sections[current_section].append(line)

    # Join multiline sections
    result = {}
    for key, value in sections.items():
        result[key] = '\n'.join(value)
    return result

def extract_field(text: str, field: str, pattern: Optional[str] = None) -> str:
    """Extract value from text using regex or field name."""
    if not text:
        return ''

    if pattern:
        match = re.search(pattern, text)
        return match.group(1).strip() if match else ''

    # Try to find field in text
    for line in text.split('\n'):
        if field.lower() in line.lower():
            parts = line.split(':', 1)
            if len(parts) > 1:
                return parts[1].strip()
    return ''

def extract_mac(text: str, interface: str) -> str:
    """Extract MAC address for specific interface from text."""
    if not text:
        return ''

    for line in text.split('\n'):
        if interface in line and 'link/ether' in line:
            parts = line.split()
            if len(parts) > 1:
                return parts[1]
    return ''

def extract_all_macs(text: str) -> Dict[str, str]:
    """Extract all MAC addresses from text."""
    macs = {}
    mac_pattern = re.compile(r'^([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})$')

    for line in text.split('\n'):
        line = line.strip()
        # Look for interface=MAC format
        if '=' in line:
            iface, mac = line.split('=', 1)
            iface = iface.strip()
            mac = mac.strip()
            if mac_pattern.match(mac):
                macs[iface] = mac
        # Look for interface MAC format
        elif 'link/ether' in line:
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0].rstrip(':')
                mac = parts[1]
                if mac_pattern.match(mac):
                    macs[iface] = mac

    return macs

def run_ssh_command(ip: str, quiet: bool = False) -> tuple[bool, str]:
    """Run SSH command to router and return (success, raw_output)."""
    try:
        if not quiet:
            print(f'[+] SSHing into {ip}...', file=sys.stderr)

        commands = (
            "echo '===OPENWRT_RELEASE==='; cat /etc/openwrt_release 2>/dev/null; "
            "echo '===BOARD==='; cat /etc/board.json 2>/dev/null | jsonfilter -e '@.model.id' 2>/dev/null; "
            "echo '===MODEL==='; cat /tmp/sysinfo/model 2>/dev/null; "
            "echo '===HOSTNAME==='; cat /proc/sys/kernel/hostname; "
            "echo '===KERNEL==='; uname -rms; "
            "echo '===UPTIME==='; uptime; "
            "echo '===MAC_BRLAN==='; cat /sys/class/net/br-lan/address 2>/dev/null; "
            "echo '===MAC_ETH0==='; cat /sys/class/net/eth0/address 2>/dev/null; "
            "echo '===MAC_ALL==='; for f in /sys/class/net/*/address; do echo \"$(basename $(dirname $f))=$(cat $f)\"; done; "
            "echo '===SERIAL==='; cat /sys/class/dmi/id/product_serial 2>/dev/null; "
            "echo '===CPU==='; cat /proc/cpuinfo 2>/dev/null | head -10; "
            "echo '===MEMORY==='; free -m 2>/dev/null || cat /proc/meminfo 2>/dev/null | head -5; "
            "echo '===FLASH==='; df -h /overlay 2>/dev/null; "
            "echo '===SSH_KEY==='; cat /etc/dropbear/authorized_keys 2>/dev/null | wc -l; "
            "echo '===SSH_FINGERPRINT==='; dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null | grep Fingerprint | awk '{print $2}'; "
            "echo '===FIREWALL==='; uci show firewall 2>/dev/null | grep -c 'Allow-SSH-WAN'; "
            "echo '===PACKAGES==='; opkg list-installed 2>/dev/null | wc -l; "
            "echo '===DMESG_BOOT==='; dmesg 2>/dev/null | head -30; "
            "echo '===LOGREAD_LAST==='; logread 2>/dev/null | tail -20; "
            "echo '===PARTITIONS==='; cat /proc/mtd 2>/dev/null; "
            "echo '===NETWORK==='; ip addr show 2>/dev/null | grep -E 'inet |link/ether'; "
            "echo '===DNS==='; cat /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null || cat /tmp/resolv.conf 2>/dev/null"
        )

        result = run_ssh(ip, commands, connect_timeout=5, timeout=20)

        if result.returncode != 0:
            print(f'[!] SSH command failed with code {result.returncode}', file=sys.stderr)
            print(f'[!] Error: {result.stderr.strip()}', file=sys.stderr)
            return False, result.stderr

        return True, result.stdout

    except subprocess.TimeoutExpired:
        print('[!] SSH connection timeout', file=sys.stderr)
        return False, ''
    except Exception as e:
        print(f'[!] SSH error: {e}', file=sys.stderr)
        return False, ''

def parse_output_to_json(output: str) -> Dict[str, Any]:
    """Parse SSH output and convert to structured JSON."""
    sections = parse_ssh_output(output)

    # Initialize result structure
    result = {
        'timestamp': None,
        'ip': None,
        'state': None,
        'identity': {},
        'firmware': {},
        'hardware': {},
        'network': {},
        'security': {},
        'diagnostics': {},
        'openwrt_release_raw': sections.get('OPENWRT_RELEASE', '')
    }

    # Set basic fields
    result['timestamp'] = None  # Will be set at the end

    # Parse sections
    for section_name, section_text in sections.items():
        section_text = section_text.strip()

        if section_name == 'OPENWRT_RELEASE':
            # Parse openwrt_release
            release = {}
            for line in section_text.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    release[key] = value
            result['firmware'] = release

        elif section_name == 'BOARD':
            # Try to parse board JSON
            try:
                board_data = json.loads(section_text)
                result['identity']['board'] = board_data.get('model', {}).get('id', '')
            except (json.JSONDecodeError, AttributeError, KeyError):
                result['identity']['board'] = section_text

        elif section_name == 'MODEL':
            result['identity']['model'] = section_text

        elif section_name == 'HOSTNAME':
            result['identity']['hostname'] = section_text

        elif section_name == 'KERNEL':
            parts = section_text.split()
            if len(parts) >= 3:
                result['firmware']['kernel'] = ' '.join(parts[:3])
            else:
                result['firmware']['kernel'] = section_text

        elif section_name == 'UPTIME':
            result['diagnostics']['uptime'] = section_text

        elif section_name == 'MAC_BRLAN':
            result['network']['macs'] = {}
            result['network']['macs']['br-lan'] = section_text

        elif section_name == 'MAC_ETH0':
            if 'macs' not in result['network']:
                result['network']['macs'] = {}
            result['network']['macs']['eth0'] = section_text

        elif section_name == 'MAC_ALL':
            result['network']['macs'].update(extract_all_macs(section_text))

        elif section_name == 'SERIAL':
            result['identity']['serial'] = section_text

        elif section_name == 'CPU':
            result['hardware']['cpu'] = section_text

        elif section_name == 'MEMORY':
            # Parse free -m output
            mem = {}
            for line in section_text.split('\n'):
                if 'Mem:' in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        mem['total'] = parts[1]
                        mem['used'] = parts[2]
                        mem['free'] = parts[3]
                        mem['available'] = parts[6]
                    break
            result['hardware']['memory_mb'] = mem

        elif section_name == 'FLASH':
            # Parse df -h output
            flash = {}
            for line in section_text.split('\n'):
                if '/overlay' in line and 'overlay' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        flash['device'] = parts[0]
                        flash['size'] = parts[1]
                        flash['used'] = parts[2]
                        flash['available'] = parts[3]
                        flash['use_percent'] = parts[4]
                    break
            result['hardware']['flash_overlay'] = flash

        elif section_name == 'PARTITIONS':
            result['hardware']['partitions'] = section_text

        elif section_name == 'SSH_KEY':
            result['security']['ssh_key_count'] = int(section_text) if section_text.isdigit() else 0

        elif section_name == 'SSH_FINGERPRINT':
            result['security']['ssh_fingerprint'] = section_text

        elif section_name == 'FIREWALL':
            result['security']['wan_ssh_rules'] = int(section_text) if section_text.isdigit() else 0

        elif section_name == 'PACKAGES':
            result['security']['packages_installed'] = int(section_text) if section_text.isdigit() else 0

        elif section_name == 'DMESG_BOOT':
            result['diagnostics']['dmesg_boot'] = section_text.split('\n')

        elif section_name == 'LOGREAD_LAST':
            result['diagnostics']['logread_last'] = section_text.split('\n')

        elif section_name == 'NETWORK':
            result['network']['addresses'] = section_text.split('\n')

        elif section_name == 'DNS':
            result['network']['dns'] = section_text.split('\n')

    # Set derived fields
    if result['identity'].get('hostname'):
        result['identity']['vendor'] = 'OpenWrt'

    # Add openwrt_release_raw to firmware for consistency
    if result['openwrt_release_raw'] and 'version' not in result['firmware']:
        for line in result['openwrt_release_raw'].split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip("'\"")
                if key == 'DISTRIB_RELEASE':
                    result['firmware']['version'] = value
                elif key == 'DISTRIB_REVISION':
                    result['firmware']['revision'] = value
                elif key == 'DISTRIB_TARGET':
                    result['firmware']['target'] = value

    # Set state
    if result['firmware'].get('version'):
        result['state'] = 'openwrt_running'
    else:
        result['state'] = 'unknown'

    return result

REPO_ROOT = Path(__file__).resolve().parent.parent
FINGERPRINTS_DIR = REPO_ROOT / "data" / "fingerprints"


def fingerprint_router(ip: str) -> Optional[Dict[str, Any]]:
    """Module API: fingerprint a router and return the result dict.

    Returns None if SSH fails. Does not print to stdout.
    """
    success, raw_output = run_ssh_command(ip, quiet=True)
    if not success:
        return None
    result = parse_output_to_json(raw_output)
    result['ip'] = ip
    result['timestamp'] = datetime.datetime.now().isoformat()
    return result


def save_fingerprint(fingerprint: Dict[str, Any], board_id: str = "") -> Optional[Path]:
    """Save a fingerprint JSON to data/fingerprints/ with timestamped filename.

    Returns the path to the saved file, or None on failure.
    """
    FINGERPRINTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = fingerprint.get("timestamp", datetime.datetime.now().isoformat())
    ts_safe = ts.replace(":", "-").replace(".", "-").replace("T", "_")
    board = board_id or fingerprint.get("identity", {}).get("board", "unknown")
    board_safe = board.replace(",", "-").replace(" ", "-")
    filename = f"{board_safe}_{ts_safe}.json"
    path = FINGERPRINTS_DIR / filename
    try:
        path.write_text(json.dumps(fingerprint, indent=2) + "\n")
        return path
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description='SSH into an OpenWrt router and collect comprehensive fingerprinting information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Auto-detect gateway, output to stdout
  %(prog)s --ip 192.168.1.1                   # Connect to specific IP
  %(prog)s --ip 192.168.1.1 --output f.json  # Save to file
  %(prog)s --interface eth0 --quiet          # Quiet mode, only errors
        '''
    )
    parser.add_argument('--ip', type=str, help='Router IP address (default: auto-detect from default gateway)')
    parser.add_argument('--interface', type=str, help='Interface to use for auto-detection')
    parser.add_argument('--output', type=str, help='Write JSON to file instead of stdout')
    parser.add_argument('--quiet', action='store_true', help='Only print errors, no progress')

    args = parser.parse_args()

    # Get IP address
    if args.ip:
        ip = args.ip
    else:
        ip = get_default_gateway(args.interface)
        if ip:
            print(f'[+] Auto-detected gateway: {ip}', file=sys.stderr)
        else:
            # Try common OpenWrt IPs
            common_ips = ['192.168.1.1', '192.168.8.1']
            print(f'[!] No default gateway found, trying common IPs...', file=sys.stderr)
            for test_ip in common_ips:
                try:
                    # Simple socket check
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(2)
                    test_socket.connect((test_ip, 22))
                    test_socket.close()
                    ip = test_ip
                    print(f'[+] Found reachable router at {ip}', file=sys.stderr)
                    break
                except socket.error:
                    continue
            else:
                print('[!] No reachable router found. Please specify --ip.', file=sys.stderr)
                sys.exit(1)

    if not ip:
        print('[!] Could not determine router IP.', file=sys.stderr)
        sys.exit(1)

    # Run SSH command
    success, raw_output = run_ssh_command(ip, args.quiet)
    if not success:
        sys.exit(1)

    result = parse_output_to_json(raw_output)
    result['ip'] = ip

    result['timestamp'] = datetime.datetime.now().isoformat() + 'Z'

    # Output JSON
    output = json.dumps(result, indent=2)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output)
            if not args.quiet:
                print(f'[+] Output written to {args.output}', file=sys.stderr)
        except Exception as e:
            print(f'[!] Failed to write output file: {e}', file=sys.stderr)
            sys.exit(1)
    else:
        sys.stdout.write(output + '\n')

    sys.exit(0)

if __name__ == '__main__':
    main()
