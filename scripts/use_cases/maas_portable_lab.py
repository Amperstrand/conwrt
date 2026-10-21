"""MAAS portable lab deployment use case.

Deploys a self-contained MAAS (Metal as a Service) instance on a
Raspberry Pi 4B with a D-Link COVR-X1860 as the bench router.
Designed for tiny portable home labs that can manage 1-5 servers.

Hardware: Pi 4B (4GB) + COVR-X1860 + USB SSD (≥32GB)
Software: Ubuntu Server 26.04 + MAAS 3.6.6 + OpenWrt 25.12.x

Per AGENTS.md (operator-private data rules) the bench network plan —
subnet, gateway, MAAS IP, DHCP pool, beacon listener — is operator-
specific and belongs in the operator's private project: this module
declares those as REQUIRED parameters and ships no committed defaults.
"""

from __future__ import annotations

import shlex
from typing import Any

from . import ParamDef, UseCase, register

# Defaults for species-level (non-operator-specific) values only.
DEFAULTS = {
    "root_partition_size": "50G",
    "maas_channel": "3.6/stable",
    "zram_percent": 75,
    "swapfile_size_mb": 2048,
    "image_arch": "amd64",
    "image_release": "noble",
    "image_url": (
        "https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/"
        "ubuntu-26.04.1-preinstalled-server-arm64+raspi.img.xz"
    ),
}

# Operator-specific (bench network plan — AGENTS.md: never committed to
# conwrt) or security-critical (no default credentials): must be supplied.
REQUIRED = [
    "uplink_ssid",
    "uplink_password",
    "bench_subnet",
    "bench_gateway",
    "maas_ip",
    "dhcp_range_start",
    "dhcp_range_end",
    "beacon_listener_ip",
    "beacon_listener_mac",
    "maas_admin_password",
]

DESCRIPTION = """Minimal MAAS for portable home labs.

Creates a wireless-uplink MAAS island:
- x1860 flashed with OpenWrt, bridged ports, WiFi STA uplink
- Pi 4B boots Ubuntu Server from USB SSD
- MAAS region+rack controller with DHCP on bench subnet
- PXE boot capability for managed servers

Serves 1-5 managed machines comfortably on 4GB RAM.
"""

POST_FLASH = True  # This use case configures post-flash, not in-image


def get_packages() -> list[str]:
    """Additional packages beyond base OpenWrt for the x1860."""
    return []


def get_first_boot_script(params: dict[str, Any]) -> str:
    """Generate the x1860 bench-mode configuration script.

    This runs on the x1860 after OpenWrt is flashed.
    """
    gateway = params["bench_gateway"]
    maas_ip = params["maas_ip"]
    ssid = params["uplink_ssid"]
    password = params["uplink_password"]
    ssh_key = params.get("ssh_key", "")
    lan_cidr = f"{gateway}/24"

    if ssh_key:
        access_block = f"""# Install the operator key (only when supplied — an absent key must
# never clobber the existing authorized_keys; AGENTS.md access rules)
_key={shlex.quote(ssh_key)}
echo "$_key" > /etc/dropbear/authorized_keys
mkdir -p /root/.ssh && cp /etc/dropbear/authorized_keys /root/.ssh/
chmod 700 /root /root/.ssh /etc/dropbear
chmod 600 /etc/dropbear/authorized_keys /root/.ssh/authorized_keys"""
    else:
        access_block = (
            "# no ssh_key supplied: existing authorized_keys left untouched"
        )

    return f"""#!/bin/sh
# x1860 "deploy MAAS and Raspberry Pi mode"
# Applied post-flash via SSH

set -e

# Identity + access
uci set system.@system[0].hostname='maas-bench'
{access_block}

# Bench bridge: both ports in one L2 segment
# DSA port names on COVR-X1860: 'ethernet' (LAN) and 'internet' (WAN)
uci add_list network.@device[0].ports='internet' 2>/dev/null || true
uci set network.lan.ipaddr={shlex.quote(lan_cidr)}
uci -q delete network.wan
uci -q delete network.wan6

# AGENTS.md: never `uci commit` an IP change without verifying the readback
_lan_set=$(uci get network.lan.ipaddr)
if [ "$_lan_set" != {shlex.quote(lan_cidr)} ]; then
    echo "ABORT: network.lan.ipaddr readback '$_lan_set' != expected '{lan_cidr}'; not committing" >&2
    exit 1
fi

# MAAS serves DHCP on the bench segment (first-boot phase 4); the
# router's own dnsmasq DHCP must not compete for PXE clients on the
# same L2 segment.
uci set dhcp.lan.ignore='1'

# 5GHz WiFi STA uplink on radio1
uci set wireless.radio1.disabled='0'
uci set wireless.radio1.channel='36'
uci set wireless.radio1.htmode='HE80'
uci set wireless.radio1.country='NO'
uci set wireless.sta5=wifi-iface
uci set wireless.sta5.device='radio1'
uci set wireless.sta5.mode='sta'
uci set wireless.sta5.ssid={shlex.quote(ssid)}
uci set wireless.sta5.encryption='psk2'
uci set wireless.sta5.key={shlex.quote(password)}
uci set wireless.sta5.network='wwan'
uci set network.wwan=interface
uci set network.wwan.proto='dhcp'
uci set network.wwan.device='phy1-sta0'

# Firewall: wwan in wan zone + management pinholes
uci add_list firewall.@zone[1].network='wwan'
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH-wan'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci add firewall rule
uci set firewall.@rule[-1].name='House-to-MAAS-mgmt'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest='lan'
uci set firewall.@rule[-1].dest_ip={shlex.quote(maas_ip)}
uci set firewall.@rule[-1].dest_port='22 5240 5248'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit
wifi config
reboot
"""


def get_pi_user_data(params: dict[str, Any]) -> str:
    """Generate the cloud-init user-data for the Pi's USB disk.

    This runs on first boot of the Ubuntu Server image.
    Includes MAAS installation, bench network configuration,
    and the monitoring/logging infrastructure.
    """
    maas_ip = params["maas_ip"]
    gateway = params["bench_gateway"]
    channel = params.get("maas_channel", DEFAULTS["maas_channel"])
    zram = params.get("zram_percent", DEFAULTS["zram_percent"])
    swap_mb = params.get("swapfile_size_mb", DEFAULTS["swapfile_size_mb"])
    admin_pw = params.get("maas_admin_password")
    if not admin_pw or admin_pw == "changeme":
        raise ValueError(
            "maas_admin_password is required and must not be the well-known "
            "'changeme' (management ports are forwarded from the uplink)"
        )
    bench_cidr = params["bench_subnet"]
    dhcp_start = params["dhcp_range_start"]
    dhcp_end = params["dhcp_range_end"]
    dns = params.get("upstream_dns") or gateway
    beacon_ip = params["beacon_listener_ip"]
    beacon_mac = params["beacon_listener_mac"]
    arch = params.get("image_arch", DEFAULTS["image_arch"])
    ssh_key = params.get("ssh_key", "")
    break_glass = params.get("break_glass_password")

    ssh_keys_block = (
        f"    ssh_authorized_keys:\n      - {ssh_key}"
        if ssh_key
        else "    # no ssh_key supplied: key-based login disabled"
    )
    chpasswd_block = (
        f"""chpasswd:
  expire: false
  users:
    - name: ubuntu
      password: {break_glass}
      type: text
"""
        if break_glass
        else "# no break_glass_password supplied: ubuntu account stays key-only"
    )

    # shlex.quote keeps generated secrets literal ($, backticks, quotes,
    # backslashes) inside the shell command line.
    q_pw = shlex.quote(admin_pw)

    return f"""#cloud-config
hostname: maas
growpart:
  mode: "off"
users:
  - name: ubuntu
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
{ssh_keys_block}
{chpasswd_block}
bootcmd:
  - bash -c 'echo "[maas-boot] bootcmd $(date +%T)" >> /var/log/maas-boot-beacons.log; echo "[maas-boot] bootcmd" > /dev/udp/{beacon_ip}/6667 2>/dev/null || true'

write_files:
  - path: /usr/local/bin/beacon
    permissions: '0755'
    content: |
      #!/bin/bash
      # bash, not sh: /dev/udp is a bash synthetic endpoint; dash would
      # treat it as a file path and silently drop every progress event
      echo "[maas-boot] $* $(date +%T)" >> /var/log/maas-boot-beacons.log
      echo "[maas-boot] $*" > /dev/udp/{beacon_ip}/6667 2>/dev/null || true
  - path: /usr/local/sbin/netconsole-start.sh
    permissions: '0755'
    content: |
      #!/bin/sh
      modprobe netconsole netconsole=6666@{maas_ip}/eth0,6666@{beacon_ip}/{beacon_mac} 2>/dev/null || true
  - path: /etc/systemd/system/maas-netconsole.service
    content: |
      [Unit]
      Description=Kernel log broadcast to bench listener
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/netconsole-start.sh
      [Install]
      WantedBy=multi-user.target
  - path: /usr/local/bin/temp-watch.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      while true; do
        T=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | cut -c1-2)
        echo "$(date +%T) ${{T}}C load=$(cut -d' ' -f1 /proc/loadavg)" >> /var/log/pi-temp.log
        [ "$T" -ge 75 ] && echo "[maas-boot] TEMP-HIGH ${{T}}C" > /dev/udp/{beacon_ip}/6667 2>/dev/null
        tail -500 /var/log/pi-temp.log > /var/log/pi-temp.log.tmp && mv /var/log/pi-temp.log.tmp /var/log/pi-temp.log
        sleep 15
      done
  - path: /etc/systemd/system/maas-temp-watch.service
    content: |
      [Unit]
      Description=Pi temperature and load monitor
      [Service]
      ExecStart=/usr/local/bin/temp-watch.sh
      Restart=always
      [Install]
      WantedBy=multi-user.target
  - path: /etc/apt/apt.conf.d/99no-cache
    content: |
      APT::Keep-Downloads "0";
  - path: /etc/systemd/journald.conf.d/99-size.conf
    content: |
      [Journal]
      SystemMaxUse=100M

runcmd:
  - |
    beacon phase1-memory-floor-start
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends -o Dpkg::Options::=--force-confold zram-tools
    printf 'ALGO=zstd\\nPERCENT={zram}\\n' > /etc/default/zramswap
    systemctl enable --now zramswap
    swapoff -a || true; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab || true
    fallocate -l {swap_mb}M /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab
    systemctl enable --now maas-netconsole.service maas-temp-watch.service
    rm -rf /usr/share/man /usr/share/doc; apt-get clean
    beacon phase1-done
  - |
    beacon phase2-snap-install-start
    snap wait system seed.loaded
    snap refresh --hold=forever
    snap install maas-test-db
    snap install maas --channel={channel}
    beacon phase2-done
  - |
    beacon phase3-maas-init-start
    INIT_OK=0
    for i in $(seq 1 12); do
      timeout 180 maas init region+rack --database-uri maas-test-db:/// --maas-url http://{maas_ip}:5240/MAAS --num-workers 2 && {{ INIT_OK=1; break; }}
      sleep 15
    done
    ADMIN_OK=0
    for i in $(seq 1 30); do
      timeout 60 maas createadmin --username admin --password {q_pw} --email admin@pi.local && {{ ADMIN_OK=1; break; }}
      sleep 10
    done
    timeout 30 maas apikey --username admin > /root/maas-apikey && chmod 600 /root/maas-apikey
    test -s /root/maas-apikey && beacon apikey-ok || beacon apikey-FAILED
  - |
    beacon phase4-bench-config-start
    LOGIN_OK=0
    for i in $(seq 1 20); do
      APIKEY=$(cat /root/maas-apikey 2>/dev/null) && timeout 60 maas login admin http://localhost:5240/MAAS "$APIKEY" 2>/dev/null && {{ LOGIN_OK=1; break; }}
      sleep 10
    done
    timeout 30 maas admin maas set-config name=upstream_dns value={dns} || true
    timeout 30 maas admin maas set-config name=network_discovery value=disabled || true
    timeout 30 maas admin subnets create cidr={bench_cidr} name=maas-bench gateway_ip={gateway} dns_servers={maas_ip} >/dev/null 2>&1 || true
    SUB=$(timeout 30 maas admin subnets read | python3 -c "import json,sys; print(next((s['id'] for s in json.load(sys.stdin) if s['cidr']=='{bench_cidr}'), ''))")
    if [ -n "$SUB" ]; then
      beacon subnet-ok
      timeout 30 maas admin ipranges create subnet="$SUB" type=dynamic start_ip={dhcp_start} end_ip={dhcp_end} >/dev/null 2>&1 && beacon range-ok || beacon range-existing
      FAB=$(timeout 30 maas admin subnet read "$SUB" | python3 -c "import json,sys; print(json.load(sys.stdin)['vlan']['fabric_id'])")
      VID=$(timeout 30 maas admin subnet read "$SUB" | python3 -c "import json,sys; print(json.load(sys.stdin)['vlan']['vid'])")
      RACK=$(timeout 30 maas admin rack-controllers read | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['system_id'])")
      timeout 60 maas admin vlan update "$FAB" "$VID" dhcp_on=True primary_rack="$RACK" >/dev/null 2>&1 && beacon dhcp-on-ok || beacon dhcp-on-FAILED
      sleep 10
      maas status | grep -q "^dhcpd.*active" && beacon dhcpd-RUNNING || beacon dhcpd-not-running
      timeout 30 maas admin boot-resources import || true
      beacon import-started
    fi
    # Completion is EARNED: only report FIRST-BOOT-COMPLETE when every
    # critical phase actually succeeded — a silent failure must not look
    # like success on the beacon channel.
    if [ "$INIT_OK" = 1 ] && [ "$ADMIN_OK" = 1 ] && [ "$LOGIN_OK" = 1 ] && [ -n "$SUB" ]; then
      beacon FIRST-BOOT-COMPLETE
    else
      beacon FIRST-BOOT-FAILED
    fi

final_message: "maas-bench provisioned after $UPTIME seconds"
"""


def get_pi_network_config(params: dict[str, Any]) -> str:
    """Generate netplan network-config for the Pi."""
    maas_ip = params["maas_ip"]
    gateway = params["bench_gateway"]
    dns = params.get("upstream_dns") or gateway

    return f"""network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      addresses: [{maas_ip}/24]
      routes:
        - to: default
          via: {gateway}
      nameservers:
        addresses: [{dns}, 1.1.1.1]
"""


def get_flash_config(params: dict[str, Any]) -> dict[str, Any]:
    """Return flash parameters for the USB disk provisioning script."""
    return {
        "image_url": params.get("image_url", DEFAULTS["image_url"]),
        "image_sha256": params.get("image_sha256"),
        "partition_size": params.get(
            "root_partition_size", DEFAULTS["root_partition_size"]
        ),
        "verify_chunks": True,
        "serial_whitelist_required": True,
        "sha256_required": True,
        "inject_boot_files": True,
    }


def validate(params: dict[str, Any]) -> list[str]:
    """Validate parameters, returning a list of error messages."""
    errors = []
    for req in REQUIRED:
        if not params.get(req):
            errors.append(f"Missing required parameter: {req}")
    if params.get("maas_admin_password") == "changeme":
        errors.append(
            "maas_admin_password must not be the well-known 'changeme' "
            "(MAAS management ports are forwarded from the uplink)"
        )
    if not params.get("ssh_key") and not params.get("break_glass_password"):
        errors.append(
            "no access path: supply ssh_key or break_glass_password "
            "(port 22 is forwarded from the uplink; a default password is unsafe)"
        )
    if params.get("break_glass_password") == "changeme":
        errors.append(
            "break_glass_password must not be the well-known 'changeme' "
            "(port 22 is forwarded from the uplink)"
        )
    if params.get("zram_percent", 0) > 90:
        errors.append("zram_percent > 90% may cause OOM under MAAS load")
    if int(params.get("swapfile_size_mb") or 0) < 1024:
        errors.append("swapfile_size_mb < 1024: MAAS init OOMs without swap")
    return errors


register(UseCase(
    name="maas-portable-lab",
    description=DESCRIPTION,
    packages=get_packages(),
    packages_remove=[],
    params={
        "uplink_ssid": ParamDef(
            type=str, required=True, allow_empty=False,
            description="SSID of the upstream 5GHz network",
        ),
        "uplink_password": ParamDef(
            type=str, required=True, allow_empty=False,
            description="WPA2 passphrase of the upstream network",
        ),
        "bench_subnet": ParamDef(
            type=str, required=True, allow_empty=False,
            description="Bench subnet (CIDR) — operator-private, never defaulted",
        ),
        "bench_gateway": ParamDef(
            type=str, required=True, allow_empty=False,
            description="Router LAN address on the bench subnet",
        ),
        "maas_ip": ParamDef(
            type=str, required=True, allow_empty=False,
            description="Static address for the MAAS Pi on the bench subnet",
        ),
        "dhcp_range_start": ParamDef(
            type=str, required=True, allow_empty=False,
            description="First address of the MAAS DHCP pool",
        ),
        "dhcp_range_end": ParamDef(
            type=str, required=True, allow_empty=False,
            description="Last address of the MAAS DHCP pool",
        ),
        "beacon_listener_ip": ParamDef(
            type=str, required=True, allow_empty=False,
            description="UDP beacon listener address — operator-private",
        ),
        "beacon_listener_mac": ParamDef(
            type=str, required=True, allow_empty=False,
            description="MAC of the beacon listener (netconsole target)",
        ),
        "maas_admin_password": ParamDef(
            type=str, required=True, allow_empty=False,
            description="MAAS admin password (generate e.g. `openssl rand -base64 24`);"
                        " 'changeme' is rejected",
        ),
        "ssh_key": ParamDef(
            type=str, default=None,
            description="Operator SSH public key; when absent, existing"
                        " authorized_keys are left untouched",
        ),
        "break_glass_password": ParamDef(
            type=str, default=None,
            description="Password for the ubuntu account; when absent the"
                        " account is key-only",
        ),
        "upstream_dns": ParamDef(
            type=str, default=None,
            description="Upstream DNS (defaults to bench_gateway)",
        ),
        "ntp_servers": ParamDef(
            type=str, default=None,
            description="NTP servers (defaults to maas_ip)",
        ),
        "root_partition_size": ParamDef(
            type=str, default=DEFAULTS["root_partition_size"],
            description="Root partition size on the USB SSD",
        ),
        "maas_channel": ParamDef(
            type=str, default=DEFAULTS["maas_channel"],
            description="snap channel for the MAAS snap",
        ),
        "zram_percent": ParamDef(
            type=int, default=DEFAULTS["zram_percent"], max_value=90,
            description="zram swap percentage",
        ),
        "swapfile_size_mb": ParamDef(
            type=int, default=DEFAULTS["swapfile_size_mb"], min_value=1024,
            description="Swapfile size in MB",
        ),
        "image_arch": ParamDef(
            type=str, default=DEFAULTS["image_arch"],
            description="Architecture for MAAS-managed images",
        ),
        "image_release": ParamDef(
            type=str, default=DEFAULTS["image_release"],
            description="Release for MAAS-managed images",
        ),
        "image_url": ParamDef(
            type=str, default=DEFAULTS["image_url"],
            description="Ubuntu Server raspi image URL",
        ),
        "image_sha256": ParamDef(
            type=str, default=None, allow_empty=False,
            description="Publisher sha256 of the image file (required by"
                        " maas_flash.py before any disk write)",
        ),
    },
    build_configure=get_first_boot_script,
    packages_via="auto",
    configure_via="ssh",
    test_status="untested",
    tested_notes="Not yet exercised on hardware; scripts reviewed only.",
    requires_capabilities=[],
))
