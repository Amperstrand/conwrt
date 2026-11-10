"""MAAS portable lab deployment use case.

Deploys a self-contained MAAS (Metal as a Service) instance on a
Raspberry Pi 4B with a D-Link COVR-X1860 as the bench router.
Designed for tiny portable home labs that can manage 1-5 servers.

Hardware: Pi 4B (4GB) + COVR-X1860 + USB SSD (≥32GB)
Software: Ubuntu Server 26.04 + MAAS 3.6.6 + OpenWrt 25.12.x
"""

from typing import Any

# Parameters with defaults — overridable via config.toml
DEFAULTS = {
    "bench_subnet": "10.50.0.0/24",
    "bench_gateway": "10.50.0.1",
    "bench_netmask": "255.255.255.0",
    "maas_ip": "10.50.0.5",
    "dhcp_range_start": "10.50.0.100",
    "dhcp_range_end": "10.50.0.200",
    "root_partition_size": "50G",
    "maas_channel": "3.6/stable",
    "zram_percent": 75,
    "swapfile_size_mb": 2048,
    "upstream_dns": None,  # defaults to bench_gateway
    "ntp_servers": None,  # defaults to maas_ip
    "image_arch": "amd64",
    "image_release": "noble",
}

REQUIRED = [
    "uplink_ssid",
    "uplink_password",
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
    gateway = params.get("bench_gateway", DEFAULTS["bench_gateway"])
    ssid = params["uplink_ssid"]
    password = params["uplink_password"]

    return f"""#!/bin/sh
# x1860 "deploy MAAS and Raspberry Pi mode"
# Applied post-flash via SSH

set -e

# Identity + access
uci set system.@system[0].hostname='maas-bench'
echo '{params.get("ssh_key", "")}' > /etc/dropbear/authorized_keys
mkdir -p /root/.ssh && cp /etc/dropbear/authorized_keys /root/.ssh/
chmod 700 /root /root/.ssh /etc/dropbear
chmod 600 /etc/dropbear/authorized_keys /root/.ssh/authorized_keys

# Bench bridge: both ports in one L2 segment
# DSA port names on COVR-X1860: 'ethernet' (LAN) and 'internet' (WAN)
uci add_list network.@device[0].ports='internet' 2>/dev/null || true
uci set network.lan.ipaddr='{gateway}/24'
uci -q delete network.wan
uci -q delete network.wan6

# 5GHz WiFi STA uplink on radio1
uci set wireless.radio1.disabled='0'
uci set wireless.radio1.channel='36'
uci set wireless.radio1.htmode='HE80'
uci set wireless.radio1.country='NO'
uci set wireless.sta5=wifi-iface
uci set wireless.sta5.device='radio1'
uci set wireless.sta5.mode='sta'
uci set wireless.sta5.ssid='{ssid}'
uci set wireless.sta5.encryption='psk2'
uci set wireless.sta5.key='{password}'
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
uci set firewall.@rule[-1].dest_ip='{params.get("maas_ip", DEFAULTS["maas_ip"])}'
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
    maas_ip = params.get("maas_ip", DEFAULTS["maas_ip"])
    gateway = params.get("bench_gateway", DEFAULTS["bench_gateway"])
    channel = params.get("maas_channel", DEFAULTS["maas_channel"])
    zram = params.get("zram_percent", DEFAULTS["zram_percent"])
    swap_mb = params.get("swapfile_size_mb", DEFAULTS["swapfile_size_mb"])
    admin_pw = params.get("maas_admin_password", "changeme")
    bench_cidr = params.get("bench_subnet", DEFAULTS["bench_subnet"])
    dhcp_start = params.get("dhcp_range_start", DEFAULTS["dhcp_range_start"])
    dhcp_end = params.get("dhcp_range_end", DEFAULTS["dhcp_range_end"])
    dns = params.get("upstream_dns") or gateway
    beacon_ip = params.get("beacon_listener_ip", "10.50.0.127")
    beacon_mac = params.get("beacon_listener_mac", "00:e0:4c:3e:7b:58")
    arch = params.get("image_arch", DEFAULTS["image_arch"])

    return f"""#cloud-config
hostname: maas
growpart:
  mode: "off"
users:
  - name: ubuntu
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - {params.get("ssh_key", "")}
chpasswd:
  expire: false
  users:
    - name: ubuntu
      password: {params.get("break_glass_password", "changeme")}
      type: text

bootcmd:
  - sh -c 'echo "[maas-boot] bootcmd $(date +%T)" >> /var/log/maas-boot-beacons.log; echo "[maas-boot] bootcmd" > /dev/udp/{beacon_ip}/6667 2>/dev/null || true'

write_files:
  - path: /usr/local/bin/beacon
    permissions: '0755'
    content: |
      #!/bin/sh
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
      #!/bin/sh
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
    for i in $(seq 1 12); do
      timeout 180 maas init region+rack --database-uri maas-test-db:/// --maas-url http://{maas_ip}:5240/MAAS --num-workers 2 && break
      sleep 15
    done
    for i in $(seq 1 30); do
      timeout 60 maas createadmin --username admin --password "{admin_pw}" --email admin@pi.local && break
      sleep 10
    done
    timeout 30 maas apikey --username admin > /root/maas-apikey && chmod 600 /root/maas-apikey
    test -s /root/maas-apikey && beacon apikey-ok || beacon apikey-FAILED
  - |
    beacon phase4-bench-config-start
    for i in $(seq 1 20); do
      APIKEY=$(cat /root/maas-apikey 2>/dev/null) && timeout 60 maas login admin http://localhost:5240/MAAS "$APIKEY" 2>/dev/null && break
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
    beacon FIRST-BOOT-COMPLETE

final_message: "maas-bench provisioned after $UPTIME seconds"
"""


def get_pi_network_config(params: dict[str, Any]) -> str:
    """Generate netplan network-config for the Pi."""
    maas_ip = params.get("maas_ip", DEFAULTS["maas_ip"])
    gateway = params.get("bench_gateway", DEFAULTS["bench_gateway"])
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
        "image_url": params.get(
            "image_url",
            "https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/"
            "ubuntu-26.04.1-preinstalled-server-arm64+raspi.img.xz",
        ),
        "partition_size": params.get("root_partition_size", "50G"),
        "verify_chunks": True,
        "serial_whitelist_required": True,
        "inject_boot_files": True,
    }


def validate(params: dict[str, Any]) -> list[str]:
    """Validate parameters, returning a list of error messages."""
    errors = []
    for req in REQUIRED:
        if not params.get(req):
            errors.append(f"Missing required parameter: {req}")
    if params.get("zram_percent", 0) > 90:
        errors.append("zram_percent > 90% may cause OOM under MAAS load")
    if int(params.get("swapfile_size_mb", 0)) < 1024:
        errors.append("swapfile_size_mb < 1024: MAAS init OOMs without swap")
    return errors
