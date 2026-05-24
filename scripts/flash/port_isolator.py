"""VLAN-based port isolation for rogue DHCP prevention during firmware flashing.

When flashing a device connected to a DSA switch port, the freshly flashed device's
DHCP server can offer leases to other network devices before the operator has a chance
to disable it. Port isolation moves the target port into its own VLAN before the device
boots, containing DHCP offers within the isolated broadcast domain.

The CPU port remains a member of the isolation VLAN so the switch can SSH/TFTP to the
target device for flashing. After flash and verification complete, the port is restored
to its default bridge membership.

Designed for OpenWrt DSA switches (Realtek RTL838x) with VLAN filtering enabled.
"""
from __future__ import annotations

import re
import shlex
import subprocess

from ssh_utils import ssh_cmd


_PORT_RE = re.compile(r"^lan[0-9]+$")
_IP_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


def _validate_port(port: str) -> None:
    if not _PORT_RE.fullmatch(port):
        raise ValueError(f"Invalid port name: {port!r} (must match lan[0-9]+)")


def _validate_ip_cidr(ip_cidr: str) -> None:
    if not _IP_CIDR_RE.fullmatch(ip_cidr):
        raise ValueError(f"Invalid IP/CIDR: {ip_cidr!r} (expected format like 192.168.1.2/24)")


class PortIsolator:
    """VLAN-based port isolation for rogue DHCP prevention during firmware flashing."""

    def __init__(self, switch_ip: str, ssh_key: str | None = None, vlan_id: int = 999):
        self.switch_ip = switch_ip
        self.ssh_key = ssh_key
        self.vlan_id = vlan_id

    def _run_ssh(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        """Run a single SSH command on the switch and return the result."""
        cmd = ssh_cmd(self.switch_ip, command, key=self.ssh_key, connect_timeout=10)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    def is_isolated(self, port: str) -> bool:
        """Check if a port is currently isolated in VLAN {vlan_id}."""
        _validate_port(port)
        result = self._run_ssh("bridge vlan show")
        if result.returncode != 0:
            return False
        # Look for the port listed with the isolation VLAN
        # Output format:
        #   port vlan ids
        #   lan5  999
        in_port_block = False
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(port):
                in_port_block = True
                if str(self.vlan_id) in stripped:
                    return True
            elif in_port_block and stripped and not stripped[0].isspace():
                # Moved to a new port block
                in_port_block = False
        return False

    def isolate(self, port: str, ip_on_isolated: str = "192.168.1.2/24") -> bool:
        """Isolate a switch port into its own VLAN.

        Steps (run via SSH to the switch):
        1. Check if port is already isolated (bridge vlan show) — idempotent
        2. Add bridge-vlan section for VLAN {vlan_id} with the port as untagged+PVID (:u*)
        3. Set local='1' (CPU port member — required for SSH/TFTP access to isolated device)
        4. uci commit network
        5. /etc/init.d/network restart
        6. Assign IP on br-lan.{vlan_id} for flash subnet

        Returns True if isolation was applied or already active.
        """
        _validate_port(port)
        _validate_ip_cidr(ip_on_isolated)

        if self.is_isolated(port):
            print(f"Port {port} already isolated in VLAN {self.vlan_id}")
            return True

        port_spec = f"{port}:u*"
        vlan_s = str(self.vlan_id)

        uci_commands = [
            "uci add network bridge-vlan",
            f"uci set network.@bridge-vlan[-1].device='br-lan'",
            f"uci set network.@bridge-vlan[-1].vlan='{vlan_s}'",
            f"uci add_list network.@bridge-vlan[-1].ports='{port_spec}'",
            "uci set network.@bridge-vlan[-1].local='1'",
            "uci commit network",
            "/etc/init.d/network restart",
        ]

        for cmd in uci_commands:
            print(f"  > {cmd}")
            result = self._run_ssh(cmd, timeout=60)
            if result.returncode != 0:
                stderr = (result.stderr or "").strip()[:300]
                print(f"  ERROR: {cmd} failed (exit {result.returncode}): {stderr}")
                return False

        # Assign IP on the isolated VLAN sub-interface
        ip_cmd = f"ip addr add {shlex.quote(ip_on_isolated)} dev br-lan.{vlan_s}"
        print(f"  > {ip_cmd}")
        result = self._run_ssh(ip_cmd)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:300]
            # "File exists" means IP already assigned — not an error
            if "File exists" not in stderr:
                print(f"  WARNING: IP assignment failed: {stderr}")

        print(f"Port {port} isolated in VLAN {self.vlan_id}")
        return True

    def restore(self, port: str, ip_on_isolated: str = "192.168.1.2/24") -> bool:
        """Restore a port from isolation back to default bridge membership.

        Steps (run via SSH to the switch):
        1. Find the bridge-vlan section with vlan={vlan_id}
        2. Delete that section
        3. uci commit network
        4. /etc/init.d/network restart
        5. Remove IP from br-lan.{vlan_id}

        Returns True if restoration was applied.
        """
        _validate_port(port)
        _validate_ip_cidr(ip_on_isolated)
        vlan_s = str(self.vlan_id)

        # Find the section index for our isolation VLAN
        find_cmd = (
            f"uci show network | grep 'bridge-vlan.*vlan={vlan_s}' "
            "| cut -d. -f2 | cut -d[ -f2 | cut -d] -f1"
        )
        print(f"  > Finding VLAN {vlan_s} section index...")
        result = self._run_ssh(find_cmd)
        if result.returncode != 0 or not result.stdout.strip():
            print(f"No VLAN {vlan_s} section found — port may not be isolated")
            return False

        section_index = result.stdout.strip().split("\n")[0].strip()
        if not section_index.isdigit():
            print(f"Unexpected section index: {section_index!r}")
            return False

        uci_commands = [
            f"uci delete network.@bridge-vlan[{section_index}]",
            "uci commit network",
            "/etc/init.d/network restart",
        ]

        for cmd in uci_commands:
            print(f"  > {cmd}")
            result = self._run_ssh(cmd, timeout=60)
            if result.returncode != 0:
                stderr = (result.stderr or "").strip()[:300]
                print(f"  ERROR: {cmd} failed (exit {result.returncode}): {stderr}")
                return False

        # Remove IP from the isolated VLAN sub-interface
        ip_cmd = f"ip addr del {shlex.quote(ip_on_isolated)} dev br-lan.{vlan_s}"
        print(f"  > {ip_cmd}")
        result = self._run_ssh(ip_cmd)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:300]
            if "Cannot find" not in stderr:
                print(f"  WARNING: IP removal failed: {stderr}")

        print(f"Port {port} restored from VLAN {self.vlan_id}")
        return True
