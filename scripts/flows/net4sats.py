"""net4sats — branded Cashu/Lightning pay-for-access WiFi gateway.

Like the ``tollgate`` flow, plus the configurationwizzard captive-portal UI and
net4sats branding. Verified end-to-end on a D-Link COVR-X1860 A1 (OpenWrt
24.10.7, mipsel_24kc, opkg). The aarch64 path (MT3000/MT6000 on OpenWrt 25.12,
apk) uses the same steps with arch/package-manager picked from the target.
"""
from __future__ import annotations

from . import Flow, Step, register
from ._gateway import CONFIGURATIONWIZZARD_URLS, gateway_base_steps, gateway_params, lan_finalize_step

register(Flow(
    name="net4sats",
    description=(
        "net4sats branded pay-for-access WiFi gateway. The 'tollgate' payment "
        "backend plus the configurationwizzard captive-portal UI and net4sats "
        "branding."
    ),
    params=gateway_params(),
    steps=gateway_base_steps() + [
        Step(
            kind="install_repo_package",
            title="Install umdns for .local mDNS resolution",
            package="umdns",
        ),
        Step(
            kind="install_package",
            title="Install the net4sats portal (configurationwizzard)",
            package="configurationwizzard",
            artifact_urls=CONFIGURATIONWIZZARD_URLS,
        ),
        Step(
            kind="hostname",
            title="Set the router hostname to net4sats",
            hostname="net4sats",
        ),
        Step(
            kind="apply_use_case",
            title="Brand the captive portal as net4sats",
            detail="Configures nodogsplash as the captive portal, restarts tollgate when the WiFi STA comes up, and sets the gateway name shown to clients to net4sats.",
            use_case="tollgate",
            use_case_params={
                "gateway_name": "net4sats",
                "gateway_domain": "net4sats.lan",
                "clientid": "mac",
                "install_hotplug": True,
                "hotplug_interface": "wwan",
            },
        ),
        lan_finalize_step(),
    ],
))
