"""Shared base for the tollgate and net4sats gateway flows.

Both flows flash stock OpenWrt, join an upstream WiFi for internet, and install
the tollgate payment backend. They diverge at the tail: ``tollgate`` applies the
generic captive-portal config, while ``net4sats`` adds the configurationwizzard
portal UI and net4sats branding. This module holds the shared head so the two
flows stay similar but distinct without duplicating the common steps.

Underscore-prefixed so the flow auto-discovery skips it (it registers no flow).
"""
from __future__ import annotations

from use_cases import ParamDef

from . import Step

TOLLGATE_ALPHA3_URLS = {
    "mipsel_24kc": "https://blossom.primal.net/2fb588b10a445555923f1325d11c3cb28220cb32f078b283d71d4d3100e58286.ipk",
    "aarch64_cortex-a53": "https://blossom.primal.net/1fcc1635a7d94a005ff270c4a44f49fb9c56b05a7fbfe01eabcba40e8d31571d.apk",
}

CONFIGURATIONWIZZARD_URLS = {
    "ipk": "https://blossom.primal.net/3bb8eae833f416f41b5dc33a1729cdd17c6303c6a936e28ece6614604334916f.ipk",
    "apk": "https://blossom.primal.net/d1951ba93958f58ece612395010a91ccbe29758569c821c1ac723e05d04c0e7b.apk",
}


def gateway_params() -> dict[str, ParamDef]:
    return {
        "upstream_ssid": ParamDef(type=str, required=True, allow_empty=False,
                                  description="Upstream WiFi SSID the router joins for internet"),
        "upstream_key": ParamDef(type=str, required=True, allow_empty=False,
                                 description="Upstream WiFi password"),
        "upstream_band": ParamDef(type=str, default="5ghz", choices=("2.4ghz", "5ghz"),
                                  description="Upstream WiFi band"),
    }


def gateway_base_steps() -> list[Step]:
    return [
        Step(
            kind="flash",
            title="Flash stock OpenWrt",
            detail="Put the router in U-Boot recovery and flash a stock OpenWrt image with conwrt. The remaining steps assume the router has rebooted to OpenWrt and is reachable at its default IP.",
        ),
        Step(
            kind="wifi_sta",
            title="Connect the router to upstream WiFi",
            detail="Configure the selected radio as a WiFi client (STA) so the router has internet for package installs.",
            band="5ghz",
            ssid_param="upstream_ssid",
            key_param="upstream_key",
            encryption="psk2",
        ),
        Step(
            kind="install_package",
            title="Install the tollgate payment backend (v0.5.0-alpha3)",
            package="tollgate-wrt",
            version="v0.5.0-alpha3",
            channel="alpha",
            artifact_urls=TOLLGATE_ALPHA3_URLS,
        ),
    ]


def lan_finalize_step() -> Step:
    return Step(
        kind="set_lan_ip",
        title="Move the LAN off 192.168.1.1",
        detail="Sets the router LAN to this model's lan_subnet so it doesn't collide with neighbour devices that default to 192.168.1.1 (e.g. a peer router sitting in U-Boot recovery). Runs last; reconnect on the new subnet afterwards.",
    )
