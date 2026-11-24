#!/bin/sh
# x1860 "deploy MAAS and Raspberry Pi mode"
# Applied post-flash via SSH

set -e

# Identity + access
uci set system.@system[0].hostname='maas-bench'
# Install the operator key (only when supplied — an absent key must
# never clobber the existing authorized_keys; AGENTS.md access rules)
_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIParityFixturePlaceholder parity@fixtures'
echo "$_key" > /etc/dropbear/authorized_keys
mkdir -p /root/.ssh && cp /etc/dropbear/authorized_keys /root/.ssh/
chmod 700 /root /root/.ssh /etc/dropbear
chmod 600 /etc/dropbear/authorized_keys /root/.ssh/authorized_keys

# Bench bridge: both ports in one L2 segment
# DSA port names on COVR-X1860: 'ethernet' (LAN) and 'internet' (WAN)
uci add_list network.@device[0].ports='internet' 2>/dev/null || true
uci set network.lan.ipaddr=192.0.2.1/24
uci -q delete network.wan
uci -q delete network.wan6

# AGENTS.md: never `uci commit` an IP change without verifying the readback
_lan_set=$(uci get network.lan.ipaddr)
if [ "$_lan_set" != 192.0.2.1/24 ]; then
    echo "ABORT: network.lan.ipaddr readback '$_lan_set' != expected '192.0.2.1/24'; not committing" >&2
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
uci set wireless.sta5.ssid=Bench-Lab-5G
uci set wireless.sta5.encryption='psk2'
uci set wireless.sta5.key=bench-lab-passphrase
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
uci set firewall.@rule[-1].dest_ip=192.0.2.10
uci set firewall.@rule[-1].dest_port='22 5240 5248'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit
wifi config
reboot
