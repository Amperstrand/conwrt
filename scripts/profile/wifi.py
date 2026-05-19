"""WiFi UCI generators shared by ASU first-boot and post-install SSH."""
from __future__ import annotations

import textwrap
from typing import Optional

from shell_safe import interface_name, radio_ref, sh_quote, wifi_band, wifi_encryption


def band_to_uci(band: str) -> str:
    wifi_band(band)
    return {
        "2.4ghz": "2g",
        "5ghz": "5g",
        "5ghz-low": "5g",
        "5ghz-high": "5g",
        "6ghz": "6g",
    }[band]


def wifi_detect_radio_shell(band: str) -> str:
    """Shell snippet that prints the radio name matching *band* on stdout."""
    uci_band = band_to_uci(band)
    return (
        "for _r in radio0 radio1 radio2 radio3; do "
        "uci -q get wireless.$_r.type >/dev/null || continue; "
        f'_b=$(uci -q get "wireless.$_r.band"); '
        f'if [ "$_b" = "{uci_band}" ]; then echo "$_r"; exit 0; fi; '
        f'_ch=$(uci -q get "wireless.$_r.channel"); '
        'case "$_ch" in '
        r"'') ;; "
        '[0-9]|1[0-4]) '
        f'if [ "{uci_band}" = "2g" ]; then echo "$_r"; exit 0; fi ;; '
        '3[0-9]|4[0-9]|5[0-9]|6[0-9]|1[0-6][0-9]) '
        f'if [ "{uci_band}" = "5g" ]; then echo "$_r"; exit 0; fi ;; '
        'esac; '
        "done"
    )


def wifi_sta_uci_lines(
    radio: str,
    ssid: str,
    encryption: str,
    key: str = "",
    network: str = "wan",
    country_code: str = "DE",
) -> list[str]:
    radio = radio_ref(radio)
    wifi_encryption(encryption)
    network = interface_name(network, "network")
    section = radio_ref(f"default_{radio}")
    lines = [
        f"uci set wireless.{radio}.disabled='0'",
        f"uci set wireless.{radio}.country='{country_code}'",
        f"uci del wireless.{section}.disabled 2>/dev/null",
        f"uci set wireless.{section}=wifi-iface",
        f"uci set wireless.{section}.device={sh_quote(radio)}",
        f"uci set wireless.{section}.mode='sta'",
        f"uci set wireless.{section}.ssid={sh_quote(ssid)}",
        f"uci set wireless.{section}.encryption={sh_quote(encryption)}",
    ]
    if key:
        lines.append(f"uci set wireless.{section}.key={sh_quote(key)}")
    lines.append(f"uci set wireless.{section}.network={sh_quote(network)}")
    return lines


def wifi_ap_uci_lines(
    radio: str,
    ssid: str,
    encryption: str,
    key: str = "",
    channel: str = "auto",
    network: str = "lan",
    country_code: str = "DE",
) -> list[str]:
    radio = radio_ref(radio)
    wifi_encryption(encryption)
    network = interface_name(network, "network")
    section = radio_ref(f"default_{radio}")
    lines = [
        f"uci set wireless.{radio}.disabled='0'",
        f"uci set wireless.{radio}.country='{country_code}'",
        f"uci del wireless.{section}.disabled 2>/dev/null",
    ]
    if channel and channel != "auto":
        lines.append(f"uci set wireless.{radio}.channel={sh_quote(channel)}")
    lines += [
        f"uci set wireless.{section}=wifi-iface",
        f"uci set wireless.{section}.device={sh_quote(radio)}",
        f"uci set wireless.{section}.mode='ap'",
        f"uci set wireless.{section}.ssid={sh_quote(ssid)}",
        f"uci set wireless.{section}.encryption={sh_quote(encryption)}",
    ]
    if key:
        lines.append(f"uci set wireless.{section}.key={sh_quote(key)}")
    lines.append(f"uci set wireless.{section}.network={sh_quote(network)}")
    return lines


def wifi_sta_firstboot_script(
    band: str,
    ssid: str,
    encryption: str,
    key: str = "",
    network: str = "wan",
    country_code: str = "DE",
) -> str:
    band_uci = band_to_uci(band)
    frags = wifi_sta_uci_lines("$_r", ssid, encryption, key, network, country_code)
    script = (
        "for _r in radio0 radio1 radio2 radio3; do "
        "uci -q get wireless.$_r.type >/dev/null || continue; "
        f'_b=$(uci -q get "wireless.$_r.band"); '
        f'if [ "$_b" = "{band_uci}" ]; then '
    )
    script += "; ".join(frags) + "; "
    script += "uci commit wireless; wifi reload; exit 0; fi; done"
    return script


def wifi_ap_firstboot_script(
    band: str,
    ssid: str,
    encryption: str,
    key: str = "",
    channel: str = "auto",
    network: str = "lan",
    country_code: str = "DE",
) -> str:
    band_uci = band_to_uci(band)
    frags = wifi_ap_uci_lines("$_r", ssid, encryption, key, channel, network, country_code)
    script = (
        "for _r in radio0 radio1 radio2 radio3; do "
        "uci -q get wireless.$_r.type >/dev/null || continue; "
        f'_b=$(uci -q get "wireless.$_r.band"); '
        f'if [ "$_b" = "{band_uci}" ]; then '
    )
    script += "; ".join(frags) + "; "
    script += "uci commit wireless; exit 0; fi; done"
    return script


def build_mgmt_wifi_script(txpower: Optional[int] = None) -> str:
    base = textwrap.dedent(
        """\
        # --- management WiFi setup ---
        RADIO_2G=""
        for radio in $(uci show wireless 2>/dev/null | grep "=wifi-device" | cut -d. -f2 | cut -d= -f1 || true); do
            band=$(uci -q get wireless.$radio.band || true)
            hwmode=$(uci -q get wireless.$radio.hwmode || true)
            case "$band" in
                2g|2.4g|2ghz|2.4ghz) RADIO_2G="$radio"; break ;; esac
            case "$hwmode" in
                11g|11ng|11axg|11bg|11b) RADIO_2G="$radio"; break ;; esac
        done
        if [ -z "$RADIO_2G" ]; then
            printf 'conwrt-mgmt-wifi: No 2.4GHz radio found, skipping\\n' >&2
            exit 0
        fi
        MAC=""
        for _ in $(seq 1 30); do
            MAC=$(cat /sys/class/net/br-lan/address 2>/dev/null || true)
            [ -n "$MAC" ] && break
            sleep 1
        done
        if [ -z "$MAC" ]; then
            MAC=$(jsonfilter -e '@.network.lan.macaddr' < /etc/board.json 2>/dev/null || true)
        fi
        if [ -z "$MAC" ]; then
            MAC=$(uci -q get wireless.$RADIO_2G.macaddr || true)
        fi
        if [ -z "$MAC" ]; then
            for iface in /sys/class/net/eth*/address /sys/class/net/*/address; do
                case "$iface" in */lo/address) continue ;; esac
                MAC=$(cat "$iface" 2>/dev/null || true)
                [ -n "$MAC" ] && break
            done
        fi
        if [ -z "$MAC" ]; then
            printf 'conwrt-mgmt-wifi: Could not determine MAC address, skipping\\n' >&2
            exit 0
        fi
        SSID="MGMT-$(printf '%s' "$MAC" | tr -d ':' | tr '[:lower:]' '[:upper:]')"
        uci set wireless.$RADIO_2G.disabled=0
        uci -q delete wireless.$RADIO_2G.country || true
"""
    )
    if txpower is not None:
        base += f"        uci set wireless.$RADIO_2G.txpower='{txpower}'\n"
    base += textwrap.dedent(
        """\
        uci -q delete network.mgmt_dev
        uci -q delete network.mgmt
        uci -q delete dhcp.mgmt
        idx=0
        while uci -q get wireless.@wifi-iface[$idx] >/dev/null 2>&1; do
            uci delete wireless.@wifi-iface[$idx]
        done
        for zone in $(uci show firewall 2>/dev/null | grep "=zone" | cut -d. -f2 | cut -d= -f1 || true); do
            name=$(uci -q get firewall.$zone.name || true)
            if [ "$name" = "mgmt" ]; then uci delete firewall.$zone; fi
        done
        uci set network.mgmt_dev=device
        uci set network.mgmt_dev.type='bridge'
        uci set network.mgmt_dev.name='br-mgmt'
        uci set network.mgmt=interface
        uci set network.mgmt.device='br-mgmt'
        uci set network.mgmt.proto='static'
        uci set network.mgmt.ipaddr='172.16.0.1'
        uci set network.mgmt.netmask='255.255.255.0'
        uci add wireless wifi-iface
        uci set wireless.@wifi-iface[-1].device="$RADIO_2G"
        uci set wireless.@wifi-iface[-1].network='mgmt'
        uci set wireless.@wifi-iface[-1].mode='ap'
        uci set wireless.@wifi-iface[-1].ssid="$SSID"
        uci set wireless.@wifi-iface[-1].hidden='1'
        uci set wireless.@wifi-iface[-1].encryption='none'
        uci set wireless.@wifi-iface[-1].disabled='0'
        uci add firewall zone
        uci set firewall.@zone[-1].name='mgmt'
        uci add_list firewall.@zone[-1].network='mgmt'
        uci set firewall.@zone[-1].input='ACCEPT'
        uci set firewall.@zone[-1].output='ACCEPT'
        uci set firewall.@zone[-1].forward='REJECT'
        uci set dhcp.mgmt=dhcp
        uci set dhcp.mgmt.interface='mgmt'
        uci set dhcp.mgmt.ignore='0'
        uci set dhcp.mgmt.start='10'
        uci set dhcp.mgmt.limit='21'
        uci set dhcp.mgmt.leasetime='12h'
        uci commit network
        uci commit wireless
        uci commit firewall
        uci commit dhcp
        /etc/init.d/network reload >/dev/null 2>&1 || true
        wifi reload >/dev/null 2>&1 || wifi >/dev/null 2>&1 || true
        /etc/init.d/firewall restart >/dev/null 2>&1 || true
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
        """
    )
    return base
