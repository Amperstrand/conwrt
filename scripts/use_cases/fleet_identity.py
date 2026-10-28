"""fleet-identity — deterministic per-device identity from MAC + fleet salt.

Sets, on first boot or via SSH apply, in one shell invocation (variables
must share one ash process):

  - root password: sha256("conwrt-fleet-v1:root:<salt>:<mac12>")[:N]
    applied via BusyBox ``passwd`` (never stored anywhere else on-device)
  - hostname: ``<prefix>-<mac12>`` (e.g. ``nr7101-aabbccddeeff``) via uci
    system + init.d restart (no ``hostname`` applet assumption)
  - management AP (fail-soft): if a wifi radio exists, the first AP
    becomes SSID ``<ssid_prefix>_<mac12>`` (e.g. ``nr7101_aabbccddeeff``)
    with the ``wifi:<network>`` domain password — the fleet_secrets twin.
    The block is guarded: no radio0/default_radio0 → silently skipped,
    so the same preset serves radio-less models.
  - rogue-DHCP disarm (dhcp.lan.ignore + ra/dhcpv6 disabled) per the
    Rogue-DHCP Discipline — devices heading for a shared bench VLAN
  - a secrets-free marker at /etc/fleet/identity for burn-in cross-check

Host-side twin: ``scripts/fleet_secrets.py`` (same derivations for the
operator and inventory).

The pattern follows tollgate-module-basic-go's identity package
(domain-separated, versioned derivations; one device — one identity),
keyed on fleet-salt+MAC instead of a generated key so credentials are
computable from the unit's label before it ever boots.

Timing note (first-boot vs SSH apply): uci-defaults may run before the
wifi driver probe has generated /etc/config/wireless, so the AP block
can legitimately skip on the first-boot path. The SSH-apply pass (post
boot, wireless config present) configures it — the runbook's unit-#1
manual verification gates on the AP being up either way.

NR7101: has a 2.4GHz MT7603 radio (corrected in models/zyxel-nr7101.json
2026-10-27 from the OpenWrt DTS + DEVICE_PACKAGES) — the AP block is
live on this model; radio0 = 2g.
"""

from __future__ import annotations

import re
from typing import Any

from fleet_secrets import (
    DEFAULT_PASSWORD_LENGTH,
    DOMAIN_VERSION,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SALT_RE,
)
from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register

_HOSTNAME_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
_WIFI_NETWORK_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$")


def _build_ops(params: dict[str, Any]) -> list[Op]:
    salt = str(params["salt"])
    prefix = str(params.get("hostname_prefix", "fleet"))
    ssid_prefix = str(params.get("ssid_prefix") or prefix)
    wifi_network = str(params.get("wifi_network", "fleet"))
    length = int(params.get("password_length", DEFAULT_PASSWORD_LENGTH))
    disarm = str(params.get("disarm_dhcp", "1")) == "1"
    configure_ap = str(params.get("configure_ap", "1")) == "1"

    if not SALT_RE.match(salt):
        raise ValueError(
            "fleet-identity: salt must be 8-128 chars of [A-Za-z0-9_-] "
            "(single-quote shell-safe; generate: openssl rand -hex 16)"
        )
    if not _HOSTNAME_PREFIX_RE.match(prefix):
        raise ValueError("fleet-identity: hostname_prefix must match [a-z0-9][a-z0-9-]{0,19}")
    if not _HOSTNAME_PREFIX_RE.match(ssid_prefix):
        raise ValueError("fleet-identity: ssid_prefix must match [a-z0-9][a-z0-9-]{0,19}")
    if not _WIFI_NETWORK_RE.match(wifi_network):
        raise ValueError("fleet-identity: wifi_network must match [a-z0-9][a-z0-9-]{0,15}")
    if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
        raise ValueError(f"fleet-identity: password_length must be {MIN_PASSWORD_LENGTH}..{MAX_PASSWORD_LENGTH}")

    ops: list[Op] = [Comment(text="--- fleet identity (MAC-derived, deterministic) ---")]

    # One ash invocation: variables (_mac/_m/_pw/_wpw) must not cross execs.
    # Every statement is single-line-safe for the &&-joined SSH transport.
    wifi_derivation = (
        f"_wpw=$(printf '%s' \"{DOMAIN_VERSION}:wifi:{wifi_network}:{salt}:$_m\" | sha256sum | cut -c1-{length}) && "
        if configure_ap
        else ""
    )
    ops.append(
        ShellCommand(
            command=(
                "_mac=$(cat /sys/class/net/eth0/address) && "
                "_m=$(printf '%s' \"$_mac\" | tr -d ':') && "
                f"_pw=$(printf '%s' \"{DOMAIN_VERSION}:root:{salt}:$_m\" | sha256sum | cut -c1-{length}) && "
                + wifi_derivation
                + 'printf \'%s\\n%s\\n\' "$_pw" "$_pw" | passwd root && '
                f'uci set system.@system[0].hostname="{prefix}-$_m" && '
                "uci commit system && "
                "mkdir -p /etc/fleet && "
                "printf 'derivation=%s\\nmac=%s\\nhostname=%s-%s\\n' "
                f"'{DOMAIN_VERSION}' '$_mac' '{prefix}' '$_m' > /etc/fleet/identity"
            )
        )
    )

    if configure_ap:
        # Guarded by radio presence: skipped whole on radio-less models or
        # when wireless config is not generated yet (first-boot timing).
        # "; "-joined inside the then-block with a trailing || true so the
        # if-statement never breaks the surrounding && chain.
        ops += [
            BlankLine(),
            Comment(text=f"--- management AP: {ssid_prefix}_<mac12>, wifi-domain key ---"),
            ShellCommand(
                command=(
                    "if uci -q get wireless.radio0 >/dev/null 2>&1 && "
                    "uci -q get wireless.default_radio0 >/dev/null 2>&1; then "
                    'uci set wireless.radio0.disabled="0"; '
                    f'uci set wireless.default_radio0.ssid="{ssid_prefix}_$_m"; '
                    'uci set wireless.default_radio0.encryption="psk2"; '
                    'uci set wireless.default_radio0.key="$_wpw"; '
                    'uci set wireless.default_radio0.network="lan"; '
                    "uci commit wireless; wifi reload 2>/dev/null || true; fi"
                )
            ),
        ]

    if disarm:
        ops += [
            BlankLine(),
            Comment(text="--- rogue-DHCP disarm (Rogue-DHCP Discipline) ---"),
            UciSet(
                config="dhcp",
                section="lan",
                values={
                    "ignore": "1",
                    "ra": "disabled",
                    "dhcpv6": "disabled",
                },
            ),
            UciCommit(config="dhcp"),
            ServiceAction(name="dnsmasq", action="restart"),
            ServiceAction(name="odhcpd", action="restart"),
            # Readback gate for the runbook's manual verify step.
            ShellCommand(command="echo fleet-identity dhcp.lan.ignore=$(uci get dhcp.lan.ignore)"),
        ]

    return ops


register(
    UseCase(
        name="fleet_identity",
        description=(
            "Deterministic per-device identity: MAC-derived root password, "
            "<prefix>-<mac12> hostname, rogue-DHCP disarm. Host twin: scripts/fleet_secrets.py"
        ),
        packages=[],
        params={
            "salt": ParamDef(
                type=str,
                required=True,
                allow_empty=False,
                description="Fleet salt (openssl rand -hex 16); [A-Za-z0-9_-]{8,128}",
            ),
            "hostname_prefix": ParamDef(type=str, default="fleet", description="Hostname prefix (e.g. nr7101)"),
            "ssid_prefix": ParamDef(
                type=str,
                default="",
                description="AP SSID prefix (default: hostname_prefix); SSID becomes <prefix>_<mac12>",
            ),
            "wifi_network": ParamDef(type=str, default="fleet", description="wifi password domain separator"),
            "password_length": ParamDef(
                type=int,
                default=DEFAULT_PASSWORD_LENGTH,
                min_value=MIN_PASSWORD_LENGTH,
                max_value=MAX_PASSWORD_LENGTH,
                description="Root/WiFi password length in hex chars",
            ),
            "disarm_dhcp": ParamDef(
                type=str, default="1", choices=("0", "1"), description="Disable DHCP/RA on lan (bench/shared segments)"
            ),
            "configure_ap": ParamDef(
                type=str, default="1", choices=("0", "1"), description="Configure management AP when a radio exists"
            ),
        },
        build_configure=lambda p: render_shell(_build_ops(p)),
        build_configure_ops=_build_ops,
        test_status="untested",
        tested_notes="derivation parity unit-tested; on-device application (incl. AP block) pending NR7101 batch — verify unit #1 manually per AGENTS before batch",
    ),
)
