"""Profile plan data structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


ProfileMode = Literal["asu_build", "post_install", "preview"]


class StepKind(Enum):
    SSH_KEY = "ssh_key"
    PASSWORD = "password"
    WAN_SSH = "wan_ssh"
    MGMT_WIFI = "mgmt_wifi"
    WIFI_STA = "wifi_sta"
    WIFI_AP = "wifi_ap"
    USE_CASE = "use_case"
    OPKG_BATCH = "opkg_batch"
    LAN_IP = "lan_ip"


@dataclass
class ProfileStep:
    kind: StepKind
    label: str
    # ASU first-boot shell fragment (uci-defaults)
    firstboot_script: str = ""
    # Post-install: opkg package names (installed before configure_script)
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
        lines: list[str] = []
        for step in self.steps:
            if not step.include_in_asu or not step.firstboot_script:
                continue
            if lines and step.firstboot_script:
                lines.append("")
            lines.append(step.firstboot_script.rstrip())
        return "\n".join(lines).strip()
