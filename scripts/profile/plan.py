"""Profile plan data structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from profile.ops import Op


ProfileMode = Literal["asu_build", "post_install", "preview"]


class StepKind(Enum):
    DHCP_DISABLE = "dhcp_disable"
    HOSTNAME = "hostname"
    SSH_KEY = "ssh_key"
    PASSWORD = "password"
    WAN_SSH = "wan_ssh"
    MGMT_WIFI = "mgmt_wifi"
    WWAN_SETUP = "wwan_setup"
    WIFI_STA = "wifi_sta"
    WIFI_AP = "wifi_ap"
    WIFI_DISABLE = "wifi_disable"
    USE_CASE = "use_case"
    OPKG_BATCH = "opkg_batch"
    LAN_IP_MAC_HASH = "lan_ip_mac_hash"
    LAN_IP = "lan_ip"
    CELLULAR = "cellular"
    TOFB = "tofb"


@dataclass
class ProfileStep:
    kind: StepKind
    label: str
    # ASU first-boot shell fragment (uci-defaults)
    firstboot_script: str = ""
    # Post-install: opkg package names (installed after WAN up, before use case scripts)
    opkg_packages: list[str] = field(default_factory=list)
    opkg_remove: list[str] = field(default_factory=list)
    # Post-install SSH: shell to run (may be multi-line)
    configure_script: str = ""
    # Post-install: detect radio then apply (wifi_sta / wifi_ap)
    wifi_detect_band: str = ""
    wifi_role: str = ""  # "sta" | "ap"
    wifi_params: dict[str, Any] = field(default_factory=dict)
    # Metadata
    use_case_name: str = ""
    skipped_reason: str = ""
    include_in_asu: bool = True
    include_in_post_install: bool = True
    # Structured operations (transport-agnostic representation)
    ops: list[Op] = field(default_factory=list)


@dataclass
class ProfilePlan:
    mode: ProfileMode
    steps: list[ProfileStep] = field(default_factory=list)
    ssh_key_cleaned: str = ""
    ssh_key_source: str = ""
    model_capabilities: list[str] = field(default_factory=list)

    def all_packages(self) -> list[str]:
        """Unique package names for ASU build or opkg install."""
        pkgs: list[str] = []
        for step in self.steps:
            for p in step.opkg_packages:
                if p not in pkgs:
                    pkgs.append(p)
        return pkgs

    def all_packages_remove(self) -> list[str]:
        remove: list[str] = []
        for step in self.steps:
            for p in step.opkg_remove:
                if p not in remove:
                    remove.append(p)
        return remove

    def asu_defaults_script(self) -> str:
        blocks: list[str] = []
        for step in self.steps:
            if not step.include_in_asu or not step.firstboot_script:
                continue
            # Subshell isolation: ASU bakes all steps into ONE uci-defaults
            # file, and some step scripts use early `exit 0` (wifi band
            # match, optional-feature skip). Without the ( ) each exit
            # would skip every later step in the chain.
            # `|| exit 1` (#229): a failed step must fail the whole file —
            # uci_apply_defaults deletes only scripts that exit 0, so this
            # keeps the file for retry instead of consuming a half-applied
            # boot (e.g. key write failed but a later block succeeded).
            blocks.append(f"(\n{step.firstboot_script.strip()}\n) || exit 1")
        return "\n\n".join(blocks).strip()
