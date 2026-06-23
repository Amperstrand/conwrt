"""tollgate — generic Bitcoin/Lightning pay-for-access WiFi gateway.

Flashes stock OpenWrt, joins an upstream WiFi, installs the tollgate payment
backend, and configures nodogsplash as the captive portal. The sibling
``net4sats`` flow adds the configurationwizzard portal UI and net4sats branding
on top of this same base.
"""
from __future__ import annotations

from . import Flow, Step, register
from ._gateway import gateway_base_steps, gateway_params, lan_finalize_step

register(Flow(
    name="tollgate",
    description=(
        "Generic TollGate Bitcoin/Lightning payment gateway. Flashes stock "
        "OpenWrt, joins upstream WiFi, installs the tollgate backend, and "
        "configures the nodogsplash captive portal. For the branded portal UI, "
        "use the 'net4sats' flow instead."
    ),
    params=gateway_params(),
    steps=gateway_base_steps() + [
        Step(
            kind="apply_use_case",
            title="Configure the captive portal",
            detail="Configures nodogsplash as the captive portal and restarts tollgate when the WiFi STA comes up.",
            use_case="tollgate",
            use_case_params={
                "gateway_name": "TollGate",
                "clientid": "mac",
                "install_hotplug": True,
                "hotplug_interface": "wwan",
            },
        ),
        lan_finalize_step(),
    ],
))
