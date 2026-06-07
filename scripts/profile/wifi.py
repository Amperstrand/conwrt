"""WiFi UCI generators shared by ASU first-boot and post-install SSH."""
from __future__ import annotations

import textwrap
from typing import Optional

from profile.ops import Op, ShellCommand, UciSet
from profile.uci_helpers import uci_add_to_wan_zone_sh
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
    network: str = "wwan",
    country_code: str = "DE",
) -> list[str]:
    radio = radio_ref(radio)
    wifi_encryption(encryption)
    network = interface_name(network, "network")
    section = radio_ref(f"default_{radio}")
    lines = [
        f"uci set wireless.{radio}.disabled='0'",
        f"uci set wireless.{radio}.country='{country_code}'",
        f"uci del wireless.{section}.disabled 2>/dev/null || true",
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
        f"uci del wireless.{section}.disabled 2>/dev/null || true",
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


def wwan_setup_ops() -> list[Op]:
    """Create wwan interface for WiFi STA WAN and add to wan firewall zone."""
    return [
        ShellCommand(command="uci set network.wwan=interface"),
        ShellCommand(command="uci set network.wwan.proto='dhcp'"),
        ShellCommand(command=uci_add_to_wan_zone_sh("wwan")),
        ShellCommand(command="uci commit network"),
        ShellCommand(command="uci commit firewall"),
    ]


def wwan_setup_shell() -> str:
    """Single-line shell for wwan setup (SSH configure_script)."""
    return (
        "uci set network.wwan=interface && "
        "uci set network.wwan.proto='dhcp' && "
        + uci_add_to_wan_zone_sh("wwan") + " && "
        "uci commit network && "
        "uci commit firewall"
    )


def wwan_setup_firstboot() -> str:
    """Multi-line shell for wwan setup (ASU first-boot script)."""
    return "\n".join([
        "# --- WWAN interface for WiFi STA ---",
        "uci set network.wwan=interface",
        "uci set network.wwan.proto='dhcp'",
        uci_add_to_wan_zone_sh("wwan"),
        "uci commit network",
        "uci commit firewall",
    ])


def wifi_sta_ops(
    radio: str,
    ssid: str,
    encryption: str,
    key: str = "",
    network: str = "wwan",
    country_code: str = "DE",
) -> list[Op]:
    """STA configuration as structured ops. Radio must be a concrete name (e.g. 'radio0')."""
    radio = radio_ref(radio)
    wifi_encryption(encryption)
    network = interface_name(network, "network")
    section = radio_ref(f"default_{radio}")
    ops: list[Op] = [
        UciSet(config="wireless", section=radio, values={"disabled": "0", "country": country_code}),
        ShellCommand(command=f"uci del wireless.{section}.disabled 2>/dev/null || true"),
        ShellCommand(command=f"uci set wireless.{section}=wifi-iface"),
        UciSet(config="wireless", section=section, values={
            "device": radio,
            "mode": "sta",
            "ssid": ssid,
            "encryption": encryption,
            **({"key": key} if key else {}),
            "network": network,
        }),
    ]
    return ops


def wifi_ap_ops(
    radio: str,
    ssid: str,
    encryption: str,
    key: str = "",
    channel: str = "auto",
    network: str = "lan",
    country_code: str = "DE",
) -> list[Op]:
    """AP configuration as structured ops. Radio must be a concrete name (e.g. 'radio0')."""
    radio = radio_ref(radio)
    wifi_encryption(encryption)
    network = interface_name(network, "network")
    section = radio_ref(f"default_{radio}")
    ops: list[Op] = [
        UciSet(config="wireless", section=radio, values={"disabled": "0", "country": country_code}),
        ShellCommand(command=f"uci del wireless.{section}.disabled 2>/dev/null || true"),
    ]
    if channel and channel != "auto":
        ops.append(UciSet(config="wireless", section=radio, values={"channel": channel}))
    ops += [
        ShellCommand(command=f"uci set wireless.{section}=wifi-iface"),
        UciSet(config="wireless", section=section, values={
            "device": radio,
            "mode": "ap",
            "ssid": ssid,
            "encryption": encryption,
            **({"key": key} if key else {}),
            "network": network,
        }),
    ]
    return ops


def wifi_sta_firstboot_script(
    band: str,
    ssid: str,
    encryption: str,
    key: str = "",
    network: str = "wwan",
    country_code: str = "DE",
) -> str:
    band_uci = band_to_uci(band)
    wwan_setup = wwan_setup_firstboot()
    frags = wifi_sta_uci_lines("$_r", ssid, encryption, key, network, country_code)
    script = (
        "for _r in radio0 radio1 radio2 radio3; do "
        "uci -q get wireless.$_r.type >/dev/null || continue; "
        f'_b=$(uci -q get "wireless.$_r.band"); '
        f'if [ "$_b" = "{band_uci}" ]; then '
    )
    script += "; ".join(frags) + "; "
    script += "uci commit wireless; wifi reload; exit 0; fi; done"
    return wwan_setup + "\n" + script


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
        _mi=0
        while uci -q get wireless.@wifi-iface[$_mi] >/dev/null 2>&1; do
            _mnet=$(uci -q get wireless.@wifi-iface[$_mi].network 2>/dev/null || true)
            if [ "$_mnet" = "mgmt" ]; then
                uci delete wireless.@wifi-iface[$_mi]
            else
                _mi=$((_mi + 1))
            fi
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
        uci set wireless.mgmt_ap=wifi-iface
        uci set wireless.mgmt_ap.device="$RADIO_2G"
        uci set wireless.mgmt_ap.network='mgmt'
        uci set wireless.mgmt_ap.mode='ap'
        uci set wireless.mgmt_ap.ssid="$SSID"
        uci set wireless.mgmt_ap.hidden='1'
        uci set wireless.mgmt_ap.encryption='none'
        uci set wireless.mgmt_ap.disabled='0'
        uci set firewall.mgmt=zone
        uci set firewall.mgmt.name='mgmt'
        uci set firewall.mgmt.input='ACCEPT'
        uci set firewall.mgmt.output='ACCEPT'
        uci set firewall.mgmt.forward='REJECT'
        uci set firewall.mgmt.network='mgmt'
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
