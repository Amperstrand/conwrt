"""conwrt project configuration loader.

Reads config.toml from the project root. Falls back gracefully when absent
(returns defaults so scripts work without a config file).

Usage:
    from config import load_config

    cfg = load_config()
    if cfg.ssh_public_key_text:
        print(cfg.ssh_public_key_text)
    if cfg.wifi_sta:
        print(cfg.wifi_sta.ssid)
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config.toml"
_DATA_DIR = _PROJECT_ROOT / "data"

_VALID_ENCRYPTIONS = {"psk2", "psk3", "sae", "none"}
_VALID_BANDS = {"2.4ghz", "5ghz", "5ghz-low", "5ghz-high"}


@dataclass
class UseCaseConfig:
    name: str
    params: dict = field(default_factory=dict)


@dataclass
class WifiSTAConfig:
    band: str = "2.4ghz"
    ssid: str = ""
    encryption: str = "psk2"
    key: str = ""


@dataclass
class WifiAPConfig:
    band: str = "2.4ghz"
    ssid: str = ""
    encryption: str = "psk2"
    key: str = ""
    channel: str = "auto"


@dataclass
class WireguardConfig:
    registration_server: str = ""
    wg_interface: str = "wg0"


@dataclass
class ConwrtConfig:
    ssh_public_key_text: str = ""
    ssh_public_key_path: str = ""
    ssh_private_key_path: str = ""
    ssh_all_keys: list[str] = field(default_factory=list)
    extra_packages: list[str] = field(default_factory=list)
    password_mode: str = "random"
    wan_ssh: bool = False
    mgmt_wifi: bool = False
    mgmt_wifi_txpower: Optional[int] = None
    wifi_sta: Optional[WifiSTAConfig] = None
    wifi_ap: Optional[WifiAPConfig] = None
    wireguard: Optional[WireguardConfig] = None
    use_cases: list[UseCaseConfig] = field(default_factory=list)

    @property
    def password_is_random(self) -> bool:
        return self.password_mode == "random"

    @property
    def password_is_key_only(self) -> bool:
        return self.password_mode == "key-only"

    @property
    def password_literal(self) -> Optional[str]:
        if self.password_mode in ("key-only", "random"):
            return None
        return self.password_mode


def _strip_key_comment(key_text: str) -> str:
    parts = key_text.strip().split()
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1]}"
    return key_text.strip()


def _is_inline_key(value: str) -> bool:
    return value.strip().startswith("ssh-")


def _assert_public_key(path_or_text: str) -> None:
    if "PRIVATE KEY" in path_or_text:
        raise ValueError(
            "[ssh].key appears to contain a private key. "
            "Only public keys are accepted — use the .pub file or inline public key text."
        )
    p = Path(path_or_text).expanduser()
    if p.is_file() and "PRIVATE KEY" in p.read_text():
        raise ValueError(
            f"[ssh].key points to a private key file: {p}. "
            "Only public key files (.pub) are accepted."
        )


def _resolve_private_from_public(pub_path: str) -> str:
    if pub_path.endswith(".pub"):
        return pub_path[:-4]
    return pub_path


def _detect_home_private_key() -> str:
    for candidate in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa"]:
        p = Path(candidate).expanduser()
        if p.is_file():
            return str(p)
    return ""


def _resolve_ssh(raw_key_value: str) -> tuple[str, str, str]:
    """Resolve the [ssh].key field into (public_key_text, public_key_path, private_key_path)."""
    if not raw_key_value:
        return "", "", _detect_home_private_key()

    _assert_public_key(raw_key_value)

    if _is_inline_key(raw_key_value):
        pub_text = _strip_key_comment(raw_key_value)
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        pub_file = _DATA_DIR / ".inline-ssh-key.pub"
        pub_file.write_text(pub_text + "\n")
        pub_path = str(pub_file)
        priv_path = _detect_home_private_key()
        return pub_text, pub_path, priv_path

    pub_path = str(Path(raw_key_value).expanduser().resolve())
    pub_text = _strip_key_comment(Path(pub_path).read_text().strip())
    priv_path = _resolve_private_from_public(pub_path)
    if not Path(priv_path).is_file():
        priv_path = _detect_home_private_key()
    return pub_text, pub_path, priv_path


def _parse_wifi_sta(table: dict) -> WifiSTAConfig:
    band = table.get("band", "2.4ghz").lower()
    if band not in _VALID_BANDS:
        raise ValueError(f"[network.sta] invalid band '{band}', expected one of: {', '.join(sorted(_VALID_BANDS))}")
    encryption = table.get("encryption", "psk2").lower()
    if encryption not in _VALID_ENCRYPTIONS:
        raise ValueError(f"[network.sta] invalid encryption '{encryption}', expected one of: {', '.join(sorted(_VALID_ENCRYPTIONS))}")
    if not table.get("ssid"):
        raise ValueError("[network.sta] ssid is required")
    return WifiSTAConfig(
        band=band,
        ssid=table["ssid"],
        encryption=encryption,
        key=table.get("key", ""),
    )


def _parse_wifi_ap(table: dict) -> WifiAPConfig:
    band = table.get("band", "2.4ghz").lower()
    if band not in _VALID_BANDS:
        raise ValueError(f"[network.ap] invalid band '{band}', expected one of: {', '.join(sorted(_VALID_BANDS))}")
    encryption = table.get("encryption", "psk2").lower()
    if encryption not in _VALID_ENCRYPTIONS:
        raise ValueError(f"[network.ap] invalid encryption '{encryption}', expected one of: {', '.join(sorted(_VALID_ENCRYPTIONS))}")
    if not table.get("ssid"):
        raise ValueError("[network.ap] ssid is required")
    return WifiAPConfig(
        band=band,
        ssid=table["ssid"],
        encryption=encryption,
        key=table.get("key", ""),
        channel=table.get("channel", "auto"),
    )


def _resolve_all_keys(raw_values: list[str]) -> list[str]:
    """Resolve a list of key specs (inline or paths) into stripped public key texts."""
    resolved = []
    for val in raw_values:
        if not val or not val.strip():
            continue
        if _is_inline_key(val):
            resolved.append(_strip_key_comment(val))
        else:
            pub_path = Path(val).expanduser().resolve()
            if pub_path.is_file():
                resolved.append(_strip_key_comment(pub_path.read_text().strip()))
    return resolved


def load_config(path: Optional[Path] = None) -> ConwrtConfig:
    """Load and validate config.toml. Returns defaults when file is missing."""
    config_path = path or _CONFIG_PATH

    if not config_path.is_file():
        return ConwrtConfig(
            ssh_private_key_path=_detect_home_private_key(),
        )

    if tomllib is None:
        print("WARNING: config.toml found but no TOML parser available. "
              "Install tomli: pip install tomli", file=sys.stderr)
        return ConwrtConfig(
            ssh_private_key_path=_detect_home_private_key(),
        )

    with open(config_path, "rb") as f:
        raw = tomllib.load(f)

    ssh_section = raw.get("ssh", {})
    asu_section = raw.get("asu", {})
    password_section = raw.get("password", {})
    network_section = raw.get("network", {})

    raw_keys = ssh_section.get("keys", [])
    if isinstance(raw_keys, str):
        raw_keys = [raw_keys]

    if raw_keys:
        all_keys = _resolve_all_keys(raw_keys)
        pub_text = all_keys[0] if all_keys else ""
        first_spec = raw_keys[0] if raw_keys else ""
        _, pub_path, priv_path = _resolve_ssh(first_spec)
    else:
        pub_text, pub_path, priv_path = _resolve_ssh(ssh_section.get("key", ""))
        all_keys = [pub_text] if pub_text else []

    password_mode = password_section.get("mode", "random")
    extra_packages = asu_section.get("extra_packages", [])
    if isinstance(extra_packages, str):
        extra_packages = [extra_packages]
    extra_packages = [pkg for pkg in extra_packages if isinstance(pkg, str) and pkg.strip()]

    wifi_sta = None
    if "sta" in network_section:
        wifi_sta = _parse_wifi_sta(network_section["sta"])

    wifi_ap = None
    if "ap" in network_section:
        wifi_ap = _parse_wifi_ap(network_section["ap"])

    uc_section = raw.get("use_cases", {})
    uc_enabled = uc_section.get("enabled", [])
    if isinstance(uc_enabled, str):
        uc_enabled = [uc_enabled]
    use_cases_list: list[UseCaseConfig] = []
    for uc_name in uc_enabled:
        uc_params = uc_section.get(uc_name, {})
        if not isinstance(uc_params, dict):
            uc_params = {}
        use_cases_list.append(UseCaseConfig(name=uc_name, params=uc_params))

    wg_section = raw.get("wireguard", {})
    wg_cfg = None
    if wg_section.get("registration_server"):
        wg_cfg = WireguardConfig(
            registration_server=wg_section.get("registration_server", ""),
            wg_interface=wg_section.get("wg_interface", "wg0"),
        )

    return ConwrtConfig(
        ssh_public_key_text=pub_text,
        ssh_public_key_path=pub_path,
        ssh_private_key_path=priv_path,
        ssh_all_keys=all_keys,
        extra_packages=extra_packages,
        password_mode=password_mode,
        wan_ssh=network_section.get("wan_ssh", False),
        mgmt_wifi=network_section.get("mgmt_wifi", False),
        mgmt_wifi_txpower=network_section.get("mgmt_wifi_txpower"),
        wifi_sta=wifi_sta,
        wifi_ap=wifi_ap,
        wireguard=wg_cfg,
        use_cases=use_cases_list,
    )
