"""Scenario matrix for the VPN bench — single source of truth.

A scenario fully describes how to switch the router to one VPN technology
variant: the conwrt use case, its params, and how to verify the tunnel.
Everything the bench measures is keyed by scenario name, so results across
runs (and routers) stay comparable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Scenario:
    name: str
    use_case: str
    params: dict = field(default_factory=dict)
    verify: str = "openvpn"          # "wireguard" | "openvpn" | "ipsec"
    group: str = "openvpn"           # for -m selection: nordlynx|openvpn|ipsec
    needs_bake: bool = False         # true if the image must carry extra packages


def _daily_ap_params() -> dict:
    out = {}
    if os.environ.get("CONWRT_BENCH_AP_SSID"):
        out["ap_ssid"] = os.environ["CONWRT_BENCH_AP_SSID"]
    if os.environ.get("CONWRT_BENCH_AP_KEY"):
        out["ap_key"] = os.environ["CONWRT_BENCH_AP_KEY"]
    return out


REPO = Path(__file__).resolve().parents[2]


def _token() -> str:
    tok = os.environ.get("CONWRT_BENCH_TOKEN", "")
    cfg = os.environ.get("CONWRT_CONFIG") or str(REPO / "config.toml")
    if not tok and Path(cfg).is_file():
        import re
        m = re.search(r'access_token\s*=\s*"([^"]+)"', Path(cfg).read_text())
        if m:
            tok = m.group(1)
    return tok


def default_scenarios() -> list[Scenario]:
    token = _token()
    ap = _daily_ap_params()
    return [
        Scenario(
            name="openvpn-udp-cbc",
            use_case="vpn-nordvpn-openvpn",
            params={"access_token": token, "server": "DE",
                    "technology": "openvpn-udp", "openvpn_cipher": "AES-256-CBC", **ap},
            verify="openvpn", group="openvpn",
        ),
        Scenario(
            name="openvpn-udp-gcm",
            use_case="vpn-nordvpn-openvpn",
            params={"access_token": token, "server": "DE",
                    "technology": "openvpn-udp", "openvpn_cipher": "AES-256-GCM", **ap},
            verify="openvpn", group="openvpn",
        ),
        Scenario(
            name="openvpn-tcp",
            use_case="vpn-nordvpn-openvpn",
            params={"access_token": token, "server": "DE",
                    "technology": "openvpn-tcp", **ap},
            verify="openvpn", group="openvpn",
        ),
        Scenario(
            name="nordlynx",
            use_case="vpn-nordvpn",
            params={"access_token": token, "server": "DE", **ap},
            verify="wireguard", group="nordlynx",
        ),
    ]


def ipsec_scenarios() -> list[Scenario]:
    """IKEv2 scenarios — require an image baked with vpn-nordvpn-ikev2."""
    token = _token()
    return [
        Scenario(
            name="ikev2-cbc-nohw",
            use_case="vpn-nordvpn-ikev2",
            params={"access_token": token, "server": "DE", "hw_accel": False},
            verify="ipsec", group="ipsec", needs_bake=True,
        ),
        Scenario(
            name="ikev2-cbc-hw",
            use_case="vpn-nordvpn-ikev2",
            params={"access_token": token, "server": "DE", "hw_accel": True},
            verify="ipsec", group="ipsec", needs_bake=True,
        ),
    ]
