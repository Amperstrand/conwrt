//! Minimal desired-state planning slice (#113): observed state + model facts
//! + one desired-state profile → a typed, inspectable, I/O-free plan.
//!
//! Planning is a **pure function** — no provider, no probes, no mutation.
//! The apply/verify executor (M7 proper) later renders the same `PlanOp`s to
//! shell or ubus, mirroring conwrt 1.x's typed ops pipeline
//! (`scripts/profile/ops.py`). The dry-run purity of this slice is proven by
//! the call-recording `MockProber`: planning after a diagnosis leaves the
//! capability journal untouched.
//!
//! Safety invariant: the planner only emits configuration plans for devices
//! whose OpenWrt identity is **confirmed** (`DeviceState::OpenWrt` requires
//! positive HTTP fingerprints, not just an SSH banner — see `state.rs`).
//! `SshOnly`/`StockVendor`/`Unknown` are rejected: firmware identity is a
//! hard precondition for configuring a device (AGENTS.md identity gates).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::state::DeviceState;
use conwrt_types::DeviceModel;

/// Smart Queue Management (CAKE/fq_codel) — port of the tested 1.x `sqm`
/// use case (`scripts/use_cases/sqm.py`, verified on OpenWrt 24.10.2 QEMU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqmProfile {
    /// Download shaper rate in Kbit/s (85–95% of the measured rate).
    pub download_kbps: u32,
    /// Upload shaper rate in Kbit/s (85–95% of the measured rate).
    pub upload_kbps: u32,
    /// UCI network name to shape (resolved to the real device at apply time).
    pub interface: String,
    /// Queue discipline: `cake` or `fq_codel`.
    pub qdisc: String,
    /// sqm-scripts qos script (e.g. `piece_of_cake.qos`, `layer_cake.qos`).
    pub script: String,
    /// Link-layer adaptation: `none`, `ethernet`, `atm`.
    pub link_layer: String,
    /// Per-packet overhead in bytes (0–512).
    pub overhead: u16,
}

impl SqmProfile {
    /// Parameter bounds mirrored from the 1.x `shell_safe` validators.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.download_kbps == 0 {
            return Err(Unsupported::InvalidParams(
                "download_kbps must be ≥ 1".into(),
            ));
        }
        if self.upload_kbps == 0 {
            return Err(Unsupported::InvalidParams("upload_kbps must be ≥ 1".into()));
        }
        if self.overhead > 512 {
            return Err(Unsupported::InvalidParams("overhead must be 0–512".into()));
        }
        if self.interface.is_empty()
            || !self
                .interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Unsupported::InvalidParams(
                "interface must be a plain UCI network name (e.g. `wan`)".into(),
            ));
        }
        Ok(())
    }
}

/// DNS-over-HTTPS via `https-dns-proxy` — port of the tested 1.x `doh`
/// use case (`scripts/use_cases/doh.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohProfile {
    /// Provider name from [`DOH_PROVIDERS`] or a custom `https://` URL.
    pub provider: String,
    /// Local listen port for the proxy (dnsmasq forwards here).
    pub listen_port: u16,
}

/// Named DoH resolver endpoints (1.x parity).
pub const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/dns-query"),
    ("quad9", "https://dns.quad9.net/dns-query"),
    ("mullvad", "https://dns.mullvad.net/dns-query"),
    ("adguard", "https://dns.adguard-dns.com/dns-query"),
];

impl DohProfile {
    /// The resolver URL this profile points at.
    #[must_use]
    pub fn resolver_url(&self) -> &str {
        for (name, url) in DOH_PROVIDERS {
            if *name == self.provider {
                return url;
            }
        }
        &self.provider
    }

    fn validate(&self) -> Result<(), Unsupported> {
        let url = self.resolver_url();
        if !url.starts_with("https://") || url.contains('\'') {
            return Err(Unsupported::InvalidParams(
                "provider must be a known name or an https:// URL".into(),
            ));
        }
        Ok(())
    }
}

/// Which phone mix a [`TetherProfile`] probes for — the four 1.x presets
/// (`tether`, `tether-android`, `tether-android-adb`, `tether-ios`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TetherVariant {
    /// Auto-detect Android or iPhone; ADB auto-enable for Android.
    Auto,
    /// Android only; tethering is enabled manually on the phone.
    Android,
    /// Android + ADB auto-enable (legacy `svc` switch, Android 14+ UI
    /// automation toggle).
    AndroidAdb,
    /// iPhone only (usbmuxd + ipheth).
    Ios,
}

impl TetherVariant {
    /// 1.x use-case name (matches `scripts/use_cases/usb_tether.py`).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            TetherVariant::Auto => "tether",
            TetherVariant::Android => "tether-android",
            TetherVariant::AndroidAdb => "tether-android-adb",
            TetherVariant::Ios => "tether-ios",
        }
    }

    /// Image/EnsurePackage set, 1.x order preserved.
    #[must_use]
    pub fn packages(self) -> &'static [&'static str] {
        match self {
            TetherVariant::Auto => &[
                "kmod-usb-net",
                "kmod-usb-net-rndis",
                "kmod-usb-net-cdc-ether",
                // Modern Android (Pixel 10 / Android 15+) exposes USB
                // tethering via CDC-NCM, NOT RNDIS (field-tested
                // 2026-10-01, conwrt-bench#46).
                "kmod-usb-net-cdc-ncm",
                "kmod-usb2",
                "usbutils",
                "kmod-usb-net-ipheth",
                "usbmuxd",
                "libimobiledevice",
                "adb",
            ],
            TetherVariant::Android => &[
                "kmod-usb-net",
                "kmod-usb-net-rndis",
                "kmod-usb-net-cdc-ether",
                "kmod-usb-net-cdc-ncm",
                "kmod-usb2",
                "usbutils",
            ],
            TetherVariant::AndroidAdb => &[
                "kmod-usb-net",
                "kmod-usb-net-rndis",
                "kmod-usb-net-cdc-ether",
                "kmod-usb-net-cdc-ncm",
                "kmod-usb2",
                "usbutils",
                "adb",
            ],
            TetherVariant::Ios => &[
                "kmod-usb-net",
                "kmod-usb-net-ipheth",
                "kmod-usb-net-cdc-ether",
                "usbmuxd",
                "libimobiledevice",
                "usbutils",
                "kmod-usb2",
            ],
        }
    }
}

/// USB tethering — WAN over USB from an Android phone and/or iPhone.
/// Port of the 1.x `tether*` presets (`scripts/use_cases/usb_tether.py`).
///
/// The 1.x module is explicit that this surface **cannot** be static UCI:
/// the USB network device is discovered at boot by walking
/// `/sys/class/net`, and the detection/setup scripts reference runtime
/// shell variables (`$USB_DEV`). The port therefore renders the same
/// lines as [`PlanOp::Shell`] ops — the 2.x twin of 1.x `ShellCommand` —
/// and golden-compares byte-for-byte against the Python builders
/// (`tests/goldens/tether*.sh`). USB-device-dependent state (the
/// `network.<interface>` section) is hardware-gated: on hardware
/// without a USB network device the script skips setup by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TetherProfile {
    /// Which phones to probe for.
    pub variant: TetherVariant,
    /// UCI network name for the USB WAN interface (1.x `interface`).
    pub interface: String,
    /// Seconds to wait for a USB network device before giving up
    /// (1.x hardcodes 45; exposed so the ring-2 VM apply, where no USB
    /// device can ever appear, does not sleep the full window).
    pub detect_timeout_secs: u32,
}

impl Default for TetherProfile {
    fn default() -> Self {
        Self {
            variant: TetherVariant::Auto,
            interface: "usbwan".into(),
            detect_timeout_secs: 45,
        }
    }
}

impl TetherProfile {
    fn validate(&self) -> Result<(), Unsupported> {
        if self.detect_timeout_secs == 0 {
            return Err(Unsupported::InvalidParams(
                "detect_timeout_secs must be ≥ 1".into(),
            ));
        }
        if self.interface.is_empty()
            || !self
                .interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(Unsupported::InvalidParams(
                "interface must be a plain UCI name (e.g. `usbwan`)".into(),
            ));
        }
        Ok(())
    }
}

/// WireGuard VPN client — port of the tested 1.x `wireguard-client`
/// preset (`scripts/use_cases/wireguard_client.py`, hardware-verified on
/// D-Link COVR-X1860 A1). Private key `'generate'` means each device
/// generates a unique Curve25519 keypair on first boot — no private key
/// ever exists in the firmware image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardClientProfile {
    /// WireGuard private key, or `generate` (1.x default) to
    /// auto-generate per device on first boot.
    pub private_key: String,
    /// VPN server public key (1.x required param).
    pub peer_public_key: String,
    /// VPN server hostname or IPv4 address (1.x required param,
    /// `shell_safe::validate_host` parity).
    pub endpoint_host: String,
    /// VPN server UDP port (1.x default 51820, `validate_port` parity).
    pub endpoint_port: u16,
    /// Optional pre-shared key (1.x default empty).
    pub peer_psk: String,
    /// Tunnel address with CIDR (1.x default `10.67.0.2/32`).
    pub address: String,
    /// DNS server routed through the tunnel (empty = use peer's).
    pub dns: String,
    /// Block all LAN→WAN traffic when the tunnel is down (1.x default).
    pub kill_switch: bool,
    /// IPs routed through the tunnel (1.x default `0.0.0.0/0, ::/0`).
    pub allowed_ips: String,
}

impl Default for WireguardClientProfile {
    fn default() -> Self {
        Self {
            private_key: "generate".into(),
            peer_public_key: String::new(),
            endpoint_host: String::new(),
            endpoint_port: 51820,
            peer_psk: String::new(),
            address: "10.67.0.2/32".into(),
            dns: String::new(),
            kill_switch: true,
            allowed_ips: "0.0.0.0/0, ::/0".into(),
        }
    }
}

/// Dotted-quad IPv4 check (1.x `_IPV4_RE` parity, no regex in core;
/// like the regex, leading zeros in an octet are accepted).
fn is_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.chars().all(|c| c.is_ascii_digit())
                && o.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Hostname-or-IPv4 check (1.x `shell_safe::validate_host` parity).
fn valid_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if is_ipv4(s) {
        return true;
    }
    // 1.x regex: `^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`
    let mut chars = s.chars();
    let first = chars.next().unwrap_or(' ');
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let last = chars.next_back().unwrap_or(first);
    last.is_ascii_alphanumeric()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

impl WireguardClientProfile {
    /// Bounds mirrored from the 1.x validators: `validate_host` /
    /// `validate_port` plus the registry-level required-param gates
    /// (`peer_public_key`, `endpoint_host`).
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.peer_public_key.is_empty() {
            return Err(Unsupported::InvalidParams(
                "peer_public_key is required (VPN server public key)".into(),
            ));
        }
        if !valid_host(&self.endpoint_host) {
            return Err(Unsupported::InvalidParams(
                "endpoint_host must be a valid hostname or IPv4 address".into(),
            ));
        }
        if self.endpoint_port == 0 {
            return Err(Unsupported::InvalidParams(
                "endpoint_port must be 1-65535".into(),
            ));
        }
        Ok(())
    }
}

/// WireGuard VPN server — port of the tested 1.x `wireguard-server`
/// preset (`scripts/use_cases/wireguard_server.py`). Remote access to
/// the local network: a `wg0` listener, a wan→router allow rule on the
/// listen port, and vpn→lan/wan forwardings. The first peer is optional
/// (1.x adds it when the client's public key is already known). Unlike
/// the client preset, 1.x declares no param validators — every value is
/// single-quoted at render time — so this port adds none either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardServerProfile {
    /// WireGuard private key, or `generate` (1.x default) to
    /// auto-generate per device on first boot.
    pub private_key: String,
    /// UDP listen port (1.x default 51820).
    pub listen_port: u16,
    /// VPN client subnet, server IP + CIDR (1.x default `10.1.99.1/24`).
    pub subnet: String,
    /// First peer's public key (empty = no peer section, 1.x default).
    pub peer1_public_key: String,
    /// First peer's allowed IPs (1.x default `10.1.99.2/32`).
    pub peer1_allowed_ips: String,
    /// First peer's pre-shared key (empty = none, 1.x default).
    pub peer1_psk: String,
}

impl Default for WireguardServerProfile {
    fn default() -> Self {
        Self {
            private_key: "generate".into(),
            listen_port: 51820,
            subnet: "10.1.99.1/24".into(),
            peer1_public_key: String::new(),
            peer1_allowed_ips: "10.1.99.2/32".into(),
            peer1_psk: String::new(),
        }
    }
}

/// Isolated guest WiFi — port of the tested 1.x `guest-wifi` preset
/// (`scripts/use_cases/guest_wifi.py`). The guest subnet is derived at
/// apply time from the live LAN IP (third octet + 1), so the address
/// lines render as shell ops exactly like 1.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestWifiProfile {
    /// Guest SSID (1.x `validate_ssid` parity: non-empty, ≤ 32 bytes,
    /// no control characters).
    pub ssid: String,
    /// WiFi password (empty = open network).
    pub key: String,
    /// Encryption mode (1.x `WIFI_ENCRYPTIONS` choice set).
    pub encryption: String,
    /// WiFi band (1.x `WIFI_BANDS` choice set).
    pub band: String,
    /// Client isolation (1.x default on).
    pub isolation: bool,
    /// UCI network/interface name (1.x `uci_name` charset).
    pub network_name: String,
}

impl Default for GuestWifiProfile {
    fn default() -> Self {
        Self {
            ssid: "Guest".into(),
            key: String::new(),
            encryption: "psk2".into(),
            band: "2.4ghz".into(),
            isolation: true,
            network_name: "guest".into(),
        }
    }
}

/// 1.x `shell_safe::WIFI_ENCRYPTIONS`.
pub const WIFI_ENCRYPTIONS: &[&str] = &[
    "none",
    "psk",
    "psk2",
    "psk3",
    "sae",
    "sae-mixed",
    "owe",
    "mixed-psk",
    "psk-mixed",
];

/// 1.x `shell_safe::WIFI_BANDS`.
pub const WIFI_BANDS: &[&str] = &["2.4ghz", "5ghz", "5ghz-low", "5ghz-high", "6ghz"];

impl GuestWifiProfile {
    /// Bounds mirrored from the 1.x validators: `validate_ssid`,
    /// `require_choice` (encryption, band), `uci_name`, and the
    /// `sh_quote` control-character rejection for `key`.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.ssid.is_empty() {
            return Err(Unsupported::InvalidParams("ssid must not be empty".into()));
        }
        if self.ssid.len() > 32 {
            return Err(Unsupported::InvalidParams(
                "ssid must be at most 32 bytes".into(),
            ));
        }
        if self.ssid.chars().any(|c| (c as u32) < 0x20) {
            return Err(Unsupported::InvalidParams(
                "ssid contains control characters".into(),
            ));
        }
        if self.key.chars().any(|c| (c as u32) < 0x20) {
            return Err(Unsupported::InvalidParams(
                "key contains control characters".into(),
            ));
        }
        if !WIFI_ENCRYPTIONS.contains(&self.encryption.as_str()) {
            return Err(Unsupported::InvalidParams(
                "encryption must be one of the 1.x WIFI_ENCRYPTIONS".into(),
            ));
        }
        if !WIFI_BANDS.contains(&self.band.as_str()) {
            return Err(Unsupported::InvalidParams(
                "band must be one of the 1.x WIFI_BANDS".into(),
            ));
        }
        if self.network_name.is_empty()
            || !self
                .network_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(Unsupported::InvalidParams(
                "network_name must contain only letters, digits, and underscores".into(),
            ));
        }
        Ok(())
    }
}

/// A desired-state profile: the outcome wanted, never the steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Eliminate bufferbloat with SQM.
    Sqm(SqmProfile),
    /// Encrypted DNS resolution for the whole LAN.
    Doh(DohProfile),
    /// USB WAN from a phone (all four 1.x tether presets).
    Tether(TetherProfile),
    /// Route traffic through a WireGuard VPN tunnel.
    WireguardClient(WireguardClientProfile),
    /// Terminate a WireGuard tunnel on this device (remote access
    /// server).
    WireguardServer(WireguardServerProfile),
    /// Isolated guest WiFi network.
    GuestWifi(GuestWifiProfile),
}

impl Profile {
    /// Stable profile identifier (matches 1.x use-case names).
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Profile::Sqm(_) => "sqm",
            Profile::Doh(_) => "doh",
            Profile::Tether(t) => t.variant.id(),
            Profile::WireguardClient(_) => "wireguard-client",
            Profile::WireguardServer(_) => "wireguard-server",
            Profile::GuestWifi(_) => "guest-wifi",
        }
    }

    /// Hardware capability tags the target model must declare (species-level,
    /// from `models/*.json` `capabilities`). SQM is pure software shaping —
    /// no requirements.
    #[must_use]
    pub fn requires(&self) -> &'static [&'static str] {
        match self {
            Profile::Sqm(_) => &[],
            Profile::Doh(_) => &[],
            Profile::Tether(_) => &["usb"],
            Profile::WireguardClient(_) => &[],
            Profile::WireguardServer(_) => &[],
            Profile::GuestWifi(_) => &["wifi"],
        }
    }
}

/// SysV init/service action (renders to `/etc/init.d/<name> <action>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    /// Enable at boot.
    Enable,
    /// (Re)start now.
    Restart,
}

impl fmt::Display for ServiceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceAction::Enable => write!(f, "enable"),
            ServiceAction::Restart => write!(f, "restart"),
        }
    }
}

/// A UCI option value: a literal, or a value the executor must resolve on
/// the device at apply time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UciValue {
    /// Fixed string, safe for single-quoted `uci set`.
    Literal(String),
    /// The Linux network device resolved from `network` (a UCI network
    /// name) at apply time — direct device, else default-route interface,
    /// else the name itself. The 1.x `wan → phy1-sta0` lesson, kept out of
    /// the plan so plans stay device-independent.
    ResolvedDevice {
        /// UCI network name to resolve, e.g. `wan`.
        network: String,
    },
}

impl fmt::Display for UciValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UciValue::Literal(v) => write!(f, "{v}"),
            UciValue::ResolvedDevice { network } => write!(f, "<device of {network}>"),
        }
    }
}

/// One typed, inspectable plan step. Rendered to shell/ubus by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOp {
    /// Install a package if missing (opkg/apk).
    EnsurePackage {
        /// opkg/apk package name.
        name: String,
    },
    /// Revert staged `/tmp/.uci` changes for a config before the first
    /// mutation (AGENTS.md: aborted sessions leave staging debris that
    /// a later commit would make permanent).
    RevertUci {
        /// UCI config name (file), e.g. `sqm`.
        config: String,
    },
    /// Delete every section of a type in a UCI config (idempotent
    /// reconfigure).
    ClearUciSections {
        /// UCI config name (file), e.g. `sqm`.
        config: String,
        /// Section type to clear, e.g. `queue`.
        section_type: String,
    },
    /// Resolve the Linux device behind a UCI network name at apply time.
    ResolveNetworkDevice {
        /// UCI network name, e.g. `wan`.
        network: String,
    },
    /// Create/replace one UCI section with ordered options.
    SetUciSection {
        /// UCI config name.
        config: String,
        /// Section name.
        section: String,
        /// Section type.
        section_type: String,
        /// Ordered `(option, value)` pairs.
        options: Vec<(String, UciValue)>,
    },
    /// Set options on an existing (possibly anonymous) section, e.g.
    /// `dhcp.@dnsmasq[0]`, without creating it.
    SetUciOptions {
        /// UCI config name.
        config: String,
        /// Section reference — named (`lan`) or anonymous (`@dnsmasq[0]`).
        section: String,
        /// Ordered `(option, value)` pairs.
        options: Vec<(String, UciValue)>,
    },
    /// Delete one option from a section (idempotent under `set -e`).
    UciDeleteOption {
        /// UCI config name.
        config: String,
        /// Section reference.
        section: String,
        /// Option to remove.
        option: String,
    },
    /// Append a value to a UCI list option.
    UciAddList {
        /// UCI config name.
        config: String,
        /// Section reference.
        section: String,
        /// List option name.
        option: String,
        /// Value to append.
        value: String,
    },
    /// Reset a whole UCI config file to empty (`uci delete <config>`).
    ResetUciConfig {
        /// UCI config name.
        config: String,
    },
    /// While-loop cleanup of stale UCI sections whose `uci show` output
    /// matches a grep pattern (1.x `uci_cleanup_sections` parity — the
    /// single source of truth for the pattern in 2.x, used by
    /// wireguard-client and guest-wifi to prevent section accumulation
    /// across reconfigure runs).
    CleanupUciSections {
        /// UCI config name, e.g. `firewall`.
        config: String,
        /// Grep pattern, e.g. `name='vpn'`.
        pattern: String,
    },
    /// Raw shell line — the escape hatch for runtime-probing scripts
    /// that cannot be static UCI (1.x `ShellCommand` parity: tether's
    /// `/sys/class/net` USB discovery, guest-wifi's radio scan, echo
    /// lines). Shell transport only; render emits the line verbatim, so
    /// builders must hand it already-shell-safe text (validators gate
    /// every interpolated value).
    Shell {
        /// Exact command line.
        command: String,
    },
    /// Persist a UCI config (`uci commit`).
    CommitUci {
        /// UCI config name.
        config: String,
    },
    /// Service management (`/etc/init.d/<name> <action>`).
    Service {
        /// Init script name.
        name: String,
        /// What to do with it.
        action: ServiceAction,
    },
}

impl fmt::Display for PlanOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanOp::EnsurePackage { name } => write!(f, "install package {name}"),
            PlanOp::RevertUci { config } => write!(f, "revert staged uci {config} baseline"),
            PlanOp::ClearUciSections {
                config,
                section_type,
            } => write!(f, "clear uci {config}.{section_type} sections"),
            PlanOp::ResolveNetworkDevice { network } => {
                write!(f, "resolve device for network {network}")
            }
            PlanOp::SetUciSection {
                config,
                section,
                section_type,
                options,
            } => {
                write!(f, "uci {config}.{section}={section_type}")?;
                for (option, value) in options {
                    write!(f, "\n  {config}.{section}.{option}={value}")?;
                }
                Ok(())
            }
            PlanOp::SetUciOptions {
                config,
                section,
                options,
            } => {
                write!(f, "uci {config}.{section} options")?;
                for (option, value) in options {
                    write!(f, "\n  {config}.{section}.{option}={value}")?;
                }
                Ok(())
            }
            PlanOp::UciDeleteOption {
                config,
                section,
                option,
            } => write!(f, "uci delete {config}.{section}.{option}"),
            PlanOp::UciAddList {
                config,
                section,
                option,
                value,
            } => write!(f, "uci add_list {config}.{section}.{option}={value}"),
            PlanOp::ResetUciConfig { config } => write!(f, "uci reset {config}"),
            PlanOp::CleanupUciSections { config, pattern } => {
                write!(f, "cleanup uci {config} sections matching {pattern}")
            }
            PlanOp::Shell { command } => write!(f, "shell: {command}"),
            PlanOp::CommitUci { config } => write!(f, "uci commit {config}"),
            PlanOp::Service { name, action } => write!(f, "service {name} {action}"),
        }
    }
}

/// How the executor will verify the plan took effect (intent, run later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    /// Human description of what is being checked.
    pub description: String,
    /// Read-only command to run on the device.
    pub command: String,
    /// Substring the output must contain.
    pub expect_contains: String,
}

/// A planned transition: what to do, and how to prove it worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Profile that produced this plan.
    pub profile_id: String,
    /// Model the plan was built for.
    pub model_id: String,
    /// Ordered steps (packages before config, config before services).
    pub ops: Vec<PlanOp>,
    /// Post-apply verification, all of which must pass.
    pub verification: Vec<VerificationCheck>,
}

/// Why a profile cannot be planned for this device/model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// Device state does not carry a **confirmed** OpenWrt identity
    /// (e.g. `SshOnly` — SSH answered, OS unconfirmed). Never plan
    /// configuration onto an unconfirmed device.
    UnconfirmedDeviceState(DeviceState),
    /// The model lacks a hardware capability the profile requires.
    MissingCapability {
        /// Model that was checked.
        model: String,
        /// Capability tag that is absent.
        capability: String,
    },
    /// Profile parameters failed validation (bounds ported from 1.x).
    InvalidParams(String),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::UnconfirmedDeviceState(state) => write!(
                f,
                "device state `{}` does not confirm OpenWrt identity; refusing to plan",
                state.as_str()
            ),
            Unsupported::MissingCapability { model, capability } => {
                write!(f, "model {model} lacks required capability `{capability}`")
            }
            Unsupported::InvalidParams(why) => write!(f, "invalid profile parameters: {why}"),
        }
    }
}

/// Check a model's declared capability tags against a profile's requirements.
fn capabilities_satisfied(model: &DeviceModel, required: &[&str]) -> Result<(), Unsupported> {
    let tags = model.capability_tags();
    for required_tag in required {
        if !tags.iter().any(|tag| tag == required_tag) {
            return Err(Unsupported::MissingCapability {
                model: model.id.clone(),
                capability: (*required_tag).to_string(),
            });
        }
    }
    Ok(())
}

/// Plan the operations to reach a profile's desired state.
///
/// Pure: consumes the already-classified state, model facts, and the profile;
/// performs no I/O and touches no provider.
pub fn plan_profile(
    state: &DeviceState,
    model: &DeviceModel,
    profile: &Profile,
) -> Result<Plan, Unsupported> {
    if *state != DeviceState::OpenWrt {
        return Err(Unsupported::UnconfirmedDeviceState(*state));
    }
    capabilities_satisfied(model, profile.requires())?;
    match profile {
        Profile::Sqm(sqm) => plan_sqm(model, sqm),
        Profile::Doh(doh) => plan_doh(model, doh),
        Profile::Tether(tether) => plan_tether(model, tether),
        Profile::WireguardClient(wg) => plan_wireguard_client(model, wg),
        Profile::WireguardServer(wg) => plan_wireguard_server(model, wg),
        Profile::GuestWifi(gw) => plan_guest_wifi(model, gw),
    }
}

fn plan_doh(model: &DeviceModel, doh: &DohProfile) -> Result<Plan, Unsupported> {
    doh.validate()?;
    let url = doh.resolver_url().to_string();
    let port = doh.listen_port;
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "https-dns-proxy".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-https-dns-proxy".into(),
        },
        PlanOp::ResetUciConfig {
            config: "https-dns-proxy".into(),
        },
        PlanOp::SetUciSection {
            config: "https-dns-proxy".into(),
            section: "main".into(),
            section_type: "https_dns_proxy".into(),
            options: vec![
                ("bootstrap_dns".into(), literal("1.1.1.1,8.8.8.8".into())),
                ("listen_addr".into(), literal("127.0.0.1".into())),
                ("listen_port".into(), literal(port.to_string())),
                ("resolver_url".into(), literal(url.clone())),
            ],
        },
        PlanOp::CommitUci {
            config: "https-dns-proxy".into(),
        },
        PlanOp::Service {
            name: "https-dns-proxy".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "https-dns-proxy".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::SetUciOptions {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            options: vec![("noresolv".into(), literal("1".into()))],
        },
        PlanOp::UciDeleteOption {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: format!("127.0.0.1#{port}"),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "resolver URL persisted".into(),
            command: "uci -q get https-dns-proxy.main.resolver_url".into(),
            expect_contains: url,
        },
        VerificationCheck {
            description: "dnsmasq forwards to the local proxy".into(),
            command: "uci -q get dhcp.@dnsmasq[0].server".into(),
            expect_contains: format!("127.0.0.1#{port}"),
        },
        VerificationCheck {
            description: "proxy enabled at boot".into(),
            command: "/etc/init.d/https-dns-proxy enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "doh".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

/// Single-quote a literal for POSIX shells (`'` → `'\''`).
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// ---- tether (1.x `scripts/use_cases/usb_tether.py`, verbatim ports) ----

/// 1.x `uci_add_to_wan_zone_sh` (scripts/profile/uci_helpers.py):
/// idempotent `wan`-zone membership by zone NAME (not index) — del_list
/// then add_list on the zone named `wan`, del_list everywhere else. The
/// body is guarded by an explicit `if` because the earlier
/// `[ ... = 'wan' ] && ...; break` form ran `add_list` on the FIRST
/// zone regardless of name (1.x comment, kept true here).
fn uci_add_to_wan_zone_sh(iface: &str) -> String {
    format!(
        "for _z in $(uci show firewall 2>/dev/null | grep '=zone' \
         | cut -d. -f2 | cut -d= -f1 || true); do \
         if [ \"$(uci -q get firewall.\"$_z\".name)\" = 'wan' ]; then \
         uci -q del_list firewall.\"$_z\".network='{iface}' 2>/dev/null; \
         uci add_list firewall.\"$_z\".network='{iface}'; \
         else \
         uci -q del_list firewall.\"$_z\".network='{iface}' 2>/dev/null; \
         fi; \
         done; true"
    )
}

/// 1.x `_detect_usb_net_device`: walk `/sys/class/net` until a device
/// bound to one of the tethering drivers appears (BRE `\|` alternation),
/// falling back to `usb0`/`usb1` existence.
fn tether_detect_script(match_android: bool, match_ios: bool, timeout: u32) -> String {
    let mut drivers: Vec<&str> = Vec::new();
    if match_android {
        drivers.extend(["rndis", "cdc_ether", "cdc_ncm", "usbnet"]);
    }
    if match_ios {
        drivers.push("ipheth");
    }
    let driver_pattern = drivers.join("\\|");
    let mut s = String::new();
    s.push_str("USB_DEV=\"\"\n");
    s.push_str(&format!("for _ in $(seq 1 {timeout}); do\n"));
    s.push_str("for dev in /sys/class/net/*; do\n");
    s.push_str("name=$(basename \"$dev\")\n");
    s.push_str("case \"$name\" in\n");
    s.push_str("lo|br-lan|eth0|wlan*) continue ;;\n");
    s.push_str("esac\n");
    s.push_str("driver=$(readlink \"$dev/device/driver\" 2>/dev/null || true)\n");
    s.push_str(&format!(
        "if echo \"$driver\" | grep -qi \"{driver_pattern}\"; then\n"
    ));
    s.push_str("USB_DEV=\"$name\"\n");
    s.push_str("break 2\n");
    s.push_str("fi\n");
    if match_ios {
        s.push_str("iface_desc=\"\"\n");
        s.push_str(
            "[ -e \"$dev/device/interface\" ] && \
             iface_desc=$(cat \"$dev/device/interface\" 2>/dev/null || true)\n",
        );
        s.push_str("if echo \"$iface_desc\" | grep -qi \"apple\\|iphone\"; then\n");
        s.push_str("USB_DEV=\"$name\"\n");
        s.push_str("break 2\n");
        s.push_str("fi\n");
    }
    s.push_str("done\n");
    s.push_str("sleep 1\n");
    s.push_str("done\n");
    s.push_str("if [ -z \"$USB_DEV\" ]; then\n");
    s.push_str("for cand in usb0 usb1; do\n");
    s.push_str("[ -e \"/sys/class/net/$cand\" ] && USB_DEV=\"$cand\" && break\n");
    s.push_str("done\n");
    s.push_str("fi\n");
    s
}

/// 1.x `_setup_interface`: create the DHCP interface on the discovered
/// `$USB_DEV`, join it to the `wan` zone, commit, and bring it up. Runs
/// only when a USB network device was found.
fn tether_setup_interface(iface: &str) -> String {
    let mut s = String::new();
    s.push_str("if [ -n \"$USB_DEV\" ]; then\n");
    s.push_str(&format!("uci set network.{iface}=interface\n"));
    s.push_str(&format!("uci set network.{iface}.proto='dhcp'\n"));
    s.push_str(&format!("uci set network.{iface}.device=\"$USB_DEV\"\n"));
    s.push_str(&format!("uci set network.{iface}.metric='20'\n"));
    s.push_str(&uci_add_to_wan_zone_sh(iface));
    s.push('\n');
    s.push_str("uci commit network\n");
    s.push_str("uci commit firewall\n");
    s.push_str(&format!("ifup {iface} 2>/dev/null || true\n"));
    s.push_str(&format!(
        "echo \"USB tethering enabled on $USB_DEV -> {iface}\"\n"
    ));
    s.push_str("else\n");
    s.push_str("echo \"USB tethering: no USB network device found, skipping\" >&2\n");
    s.push_str("fi\n");
    s
}

fn tether_start_usbmuxd() -> &'static str {
    "/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &\n"
}

/// 1.x `_adb_hotplug_script` (raw string, byte-for-byte). Two enablement
/// methods per USB bind with exponential backoff: `svc usb setFunctions
/// rndis` (Android ≤ 12) and UI automation — Android 14+ rejects
/// privileged tethering APIs from plain adb shell, but uiautomator dump +
/// `input tap` simulate a user toggling the switch (Pixel 10 / Android
/// 15, field-verified 2026-10-01). Installed as a hotplug hook; the
/// heredoc body reassembles because consecutive `Shell` ops render as
/// adjacent lines.
fn tether_adb_hotplug_script() -> &'static str {
    // The 1.x source is a Python RAW string whose first line is a lone
    // `\` — 1.x renders it as its own script line (a shell line
    // continuation, harmless), and byte parity keeps it.
    "\\\n\
mkdir -p /etc/hotplug.d/usb
cat > /etc/hotplug.d/usb/99-usb-tether-adb << 'HOTPLUG_EOF'
[ \"$ACTION\" = \"bind\" ] || exit 0
[ \"$PRODUCT\" ] || exit 0
(
HOME=/root
export HOME
command -v adb >/dev/null 2>&1 || exit 0
DELAY=1
attempt=0
while [ $attempt -lt 7 ]; do
    attempt=$((attempt + 1))
    sleep $DELAY
    if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
        exit 0
    fi
    STATE=$(adb get-state 2>/dev/null)
    if [ \"$STATE\" = \"device\" ]; then
        adb shell svc usb setFunctions rndis 2>/dev/null
        sleep 3
        if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
            logger -t usb-tether \"ADB svc enabled tethering (attempt $attempt)\"
            exit 0
        fi
        adb shell input keyevent KEYCODE_WAKEUP 2>/dev/null
        sleep 1
        adb shell am start -a android.settings.TETHER_SETTINGS 2>/dev/null
        sleep 3
        adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
        UI=$(adb shell cat /sdcard/ui.xml 2>/dev/null)
        USB_ROW=$(echo \"$UI\" | grep -oE 'USB.tethering[^>]*bounds=\"\\[[0-9]+,[0-9]+' | grep -oE '[0-9]+,[0-9]+' | head -1)
        USB_Y=$(echo \"$USB_ROW\" | cut -d, -f2)
        if [ -n \"$USB_Y\" ]; then
            USB_Y_CENTER=$((USB_Y + 28))
            SWITCH=$(echo \"$UI\" | grep -oE \"Switch[^>]*bounds=\\\"\\[[0-9]+,${USB_Y_CENTER}\" | grep -oE '\\[[0-9]+,' | grep -oE '[0-9]+' | head -1)
            if [ -n \"$SWITCH\" ]; then
                SWITCH_CENTER=$((SWITCH + 65))
                adb shell input tap $SWITCH_CENTER $USB_Y_CENTER 2>/dev/null
                sleep 3
                if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
                    logger -t usb-tether \"ADB UI toggle enabled tethering (attempt $attempt)\"
                    exit 0
                fi
            fi
        fi
    fi
    DELAY=$((DELAY * 2))
done
logger -t usb-tether \"ADB tethering gave up after $attempt attempts\"
) &
HOTPLUG_EOF
"
}

/// 1.x `_shell_lines_to_ops` shape: strip each line, drop empties
/// (BlankLine ops are cosmetic and filtered by the golden comparator).
fn shell_lines(ops: &mut Vec<PlanOp>, text: &str) {
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            ops.push(PlanOp::Shell {
                command: line.into(),
            });
        }
    }
}

/// 1.x kill-switch tunnel verification (tail of the wireguard script):
/// if no WireGuard handshake appears within 30 s, the kill switch rule
/// is deleted so the site regains WAN (fail-open by design — 1.x
/// behavior).
const WIREGUARD_KILLSWITCH_VERIFY: &str = "i=0; while [ $i -lt 30 ]; do \
if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then \
echo 'WG kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; \
echo 'WG kill-switch: tunnel failed \u{2014} removing kill switch to restore WAN'; \
uci delete firewall.wg_client_killswitch; uci commit firewall; fw4 restart";

fn plan_tether(model: &DeviceModel, tether: &TetherProfile) -> Result<Plan, Unsupported> {
    tether.validate()?;
    let iface = &tether.interface;
    let mut ops: Vec<PlanOp> = tether
        .variant
        .packages()
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    let script = match tether.variant {
        TetherVariant::Auto => {
            format!(
                "{}{}\n{}\n{}",
                tether_start_usbmuxd(),
                tether_detect_script(true, true, tether.detect_timeout_secs),
                tether_setup_interface(iface),
                tether_adb_hotplug_script()
            )
        }
        TetherVariant::Android => format!(
            "{}\n{}\n",
            tether_detect_script(true, false, tether.detect_timeout_secs),
            tether_setup_interface(iface)
        ),
        TetherVariant::AndroidAdb => format!(
            "{}\n{}\n{}",
            tether_detect_script(true, false, tether.detect_timeout_secs),
            tether_setup_interface(iface),
            tether_adb_hotplug_script()
        ),
        TetherVariant::Ios => format!(
            "{}{}\n{}\n",
            tether_start_usbmuxd(),
            tether_detect_script(false, true, tether.detect_timeout_secs),
            tether_setup_interface(iface)
        ),
    };
    shell_lines(&mut ops, &script);

    // Verification is split by what is provable without USB hardware:
    // ADB-carrying variants install a hotplug hook (filesystem proof,
    // VM-checkable); the network.<iface> section only exists once a real
    // USB network device answers (hardware-gated).
    let verification = if matches!(
        tether.variant,
        TetherVariant::Auto | TetherVariant::AndroidAdb
    ) {
        vec![VerificationCheck {
            description: "ADB hotplug hook installed".into(),
            command: "test -f /etc/hotplug.d/usb/99-usb-tether-adb && echo yes".into(),
            expect_contains: "yes".into(),
        }]
    } else {
        vec![VerificationCheck {
            description: "USB WAN interface configured (hardware-gated)".into(),
            command: format!("uci -q get network.{iface}.proto"),
            expect_contains: "dhcp".into(),
        }]
    };
    Ok(Plan {
        profile_id: tether.variant.id().into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_wireguard_client(
    model: &DeviceModel,
    wg: &WireguardClientProfile,
) -> Result<Plan, Unsupported> {
    wg.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("wireguard".into())),
                ("private_key".into(), literal(wg.private_key.clone())),
                ("addresses".into(), literal(wg.address.clone())),
            ],
        },
    ];
    if !wg.dns.is_empty() {
        ops.push(PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "dns".into(),
            value: wg.dns.clone(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "network".into(),
        section: "wg0_peer".into(),
        section_type: "wireguard_wg0".into(),
        options: vec![
            ("public_key".into(), literal(wg.peer_public_key.clone())),
            ("endpoint_host".into(), literal(wg.endpoint_host.clone())),
            (
                "endpoint_port".into(),
                literal(wg.endpoint_port.to_string()),
            ),
            ("allowed_ips".into(), literal(wg.allowed_ips.clone())),
            ("route_allowed_ips".into(), literal("1".into())),
            ("persistent_keepalive".into(), literal("25".into())),
        ],
    });
    if !wg.peer_psk.is_empty() {
        ops.push(PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0_peer".into(),
            options: vec![("preshared_key".into(), literal(wg.peer_psk.clone()))],
        });
    }
    // Named firewall sections + while-loop cleanup of stale anonymous
    // sections to prevent accumulation across reconfigure runs.
    ops.extend([
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "dest='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='KillSwitch-Reject-NonVPN'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_vpn".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("REJECT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("wg0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_fwd".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("vpn".into())),
            ],
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    ops.extend([
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo 'WireGuard client configured: {}:{}'",
                wg.endpoint_host, wg.endpoint_port
            ),
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::Shell {
            command: WIREGUARD_KILLSWITCH_VERIFY.into(),
        });
    }
    // The kill-switch rule is intentionally NOT verified post-apply: the
    // verify loop removes it when no handshake appears (fail-open).
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "peer endpoint persisted".into(),
            command: "uci -q get network.wg0_peer.endpoint_host".into(),
            expect_contains: wg.endpoint_host.clone(),
        },
        VerificationCheck {
            description: "peer public key persisted".into(),
            command: "uci -q get network.wg0_peer.public_key".into(),
            expect_contains: wg.peer_public_key.clone(),
        },
    ];
    Ok(Plan {
        profile_id: "wireguard-client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_wireguard_server(
    model: &DeviceModel,
    wg: &WireguardServerProfile,
) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "qrencode".into(),
        },
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("wireguard".into())),
                ("private_key".into(), literal(wg.private_key.clone())),
                ("listen_port".into(), literal(wg.listen_port.to_string())),
            ],
        },
        PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "addresses".into(),
            value: wg.subnet.clone(),
        },
        PlanOp::Shell {
            command: "mkdir -p /etc/wireguard && \
                      wg show wg0 public-key > /etc/wireguard/server_public_key \
                      2>/dev/null || true"
                .into(),
        },
    ];
    if !wg.peer1_public_key.is_empty() {
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0_peer1".into(),
            section_type: "wireguard_wg0".into(),
            options: vec![
                ("public_key".into(), literal(wg.peer1_public_key.clone())),
                ("allowed_ips".into(), literal(wg.peer1_allowed_ips.clone())),
                ("route_allowed_ips".into(), literal("1".into())),
            ],
        });
        if !wg.peer1_psk.is_empty() {
            ops.push(PlanOp::SetUciOptions {
                config: "network".into(),
                section: "wg0_peer1".into(),
                options: vec![("preshared_key".into(), literal(wg.peer1_psk.clone()))],
            });
        }
    }
    // Named firewall sections + while-loop cleanup of stale anonymous
    // sections to prevent accumulation across reconfigure runs.
    ops.extend([
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='Allow-WireGuard'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_vpn".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("ACCEPT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("wg0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_lan".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("vpn".into())),
                ("dest".into(), literal("lan".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_wan".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("vpn".into())),
                ("dest".into(), literal("wan".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_allow".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-WireGuard".into())),
                ("src".into(), literal("wan".into())),
                ("dest_port".into(), literal(wg.listen_port.to_string())),
                ("proto".into(), literal("udp".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"WireGuard server configured: port {}, subnet {}\"",
                wg.listen_port, wg.subnet
            ),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "listen port persisted".into(),
            command: "uci -q get network.wg0.listen_port".into(),
            expect_contains: wg.listen_port.to_string(),
        },
        VerificationCheck {
            description: "wan allow rule persisted".into(),
            command: "uci -q get firewall.wg_server_allow.name".into(),
            expect_contains: "Allow-WireGuard".into(),
        },
    ];
    Ok(Plan {
        profile_id: "wireguard-server".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_guest_wifi(model: &DeviceModel, gw: &GuestWifiProfile) -> Result<Plan, Unsupported> {
    gw.validate()?;
    let net = &gw.network_name;
    let ssid_q = shell_quote(&gw.ssid);
    let key_q = shell_quote(&gw.key);
    let band_short = format!("{}g", gw.band.chars().next().unwrap_or('2'));
    let isolated = if gw.isolation { "1" } else { "0" };
    let literal = |v: String| UciValue::Literal(v);
    let section = |config: &str,
                   section: &str,
                   section_type: &str,
                   options: Vec<(&str, String)>| PlanOp::SetUciSection {
        config: config.into(),
        section: section.into(),
        section_type: section_type.into(),
        options: options
            .into_iter()
            .map(|(k, v)| (k.into(), literal(v)))
            .collect(),
    };

    // Guest subnet derives from the live LAN IP (third octet + 1) at
    // apply time — these lines are shell ops, exactly like 1.x.
    let mut ops = vec![
        PlanOp::Shell {
            command: "_lan_ip=$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
                .into(),
        },
        PlanOp::Shell {
            command: "_guest_o3=$(echo \"$_lan_ip\" | cut -d. -f3)".into(),
        },
        PlanOp::Shell {
            command: "_guest_o3=$((_guest_o3 + 1))".into(),
        },
        PlanOp::Shell {
            command: "[ \"$_guest_o3\" -gt 255 ] && _guest_o3=0".into(),
        },
        PlanOp::Shell {
            command: "_guest_prefix=$(echo \"$_lan_ip\" | cut -d. -f1-2).$_guest_o3".into(),
        },
        section("network", net, "interface", vec![]),
        PlanOp::Shell {
            command: format!("uci set network.{net}.ipaddr=\"$_guest_prefix.1\""),
        },
        PlanOp::SetUciOptions {
            config: "network".into(),
            section: net.clone(),
            options: vec![
                ("proto".into(), literal("static".into())),
                ("netmask".into(), literal("255.255.255.0".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "network".into(),
        },
        section(
            "dhcp",
            net,
            "dhcp",
            vec![
                ("interface", net.clone()),
                ("start", "100".into()),
                ("limit", "50".into()),
                ("leasetime", "1h".into()),
            ],
        ),
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        section(
            "firewall",
            net,
            "zone",
            vec![
                ("name", net.clone()),
                ("network", net.clone()),
                ("input", "REJECT".into()),
                ("output", "ACCEPT".into()),
                ("forward", "REJECT".into()),
            ],
        ),
        section(
            "firewall",
            &format!("{net}_fwd"),
            "forwarding",
            vec![("src", net.clone()), ("dest", "wan".into())],
        ),
        section(
            "firewall",
            &format!("{net}_dns"),
            "rule",
            vec![
                ("name", format!("Allow-DNS-{net}")),
                ("src", net.clone()),
                ("dest_port", "53".into()),
                ("proto", "tcpudp".into()),
                ("target", "ACCEPT".into()),
            ],
        ),
        section(
            "firewall",
            &format!("{net}_dhcp"),
            "rule",
            vec![
                ("name", format!("Allow-DHCP-{net}")),
                ("src", net.clone()),
                ("dest_port", "67-68".into()),
                ("proto", "udp".into()),
                ("target", "ACCEPT".into()),
            ],
        ),
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::CleanupUciSections {
            config: "wireless".into(),
            pattern: format!("network='{net}'"),
        },
    ];
    // Radio discovery by band (1.x `_radio` loop) + named VAP section
    // (idempotent — overwrites on reconfigure). NOTE (1.x parity): an
    // unguarded `uci get` for a missing radio fails the line; on the
    // 1.x apply path this script runs without `set -e` member-joins —
    // apply targets are wifi hardware where the loop terminates before
    // missing radios.
    let mut radio_line = format!(
        "_radio=\"\"; for _r in radio0 radio1 radio2 radio3; do \
         _b=$(uci get wireless.${{_r}}.band 2>/dev/null); \
         if [ \"$_b\" = \"{band_short}\" ]; then _radio=$_r; break; fi; done; \
         if [ -n \"$_radio\" ]; then \
         uci set wireless.guest_ap=wifi-iface; \
         uci set wireless.guest_ap.device=$_radio; \
         uci set wireless.guest_ap.mode=ap; \
         uci set wireless.guest_ap.ssid={ssid_q}; \
         uci set wireless.guest_ap.encryption={}; \
         ",
        gw.encryption
    );
    if !gw.key.is_empty() {
        radio_line.push_str(&format!("uci set wireless.guest_ap.key={key_q}; "));
    }
    radio_line.push_str(&format!(
        "uci set wireless.guest_ap.network={net}; \
         uci set wireless.guest_ap.isolate={isolated}; fi"
    ));
    ops.push(PlanOp::Shell {
        command: radio_line,
    });
    ops.extend([
        PlanOp::CommitUci {
            config: "wireless".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Service {
            name: "firewall".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"Guest WiFi configured: SSID={ssid_q} network={net} isolated={isolated}\""
            ),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "guest firewall zone persisted".into(),
            command: format!("uci -q get firewall.{net}.name"),
            expect_contains: net.clone(),
        },
        VerificationCheck {
            description: "guest DNS rule persisted".into(),
            command: format!("uci -q get firewall.{net}_dns.dest_port"),
            expect_contains: "53".into(),
        },
    ];
    Ok(Plan {
        profile_id: "guest-wifi".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn device_var(network: &str) -> String {
    let sanitized: String = network
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("_conwrt_dev_{sanitized}")
}

/// UCI identifier keys render bare (1.x convention); non-identifier
/// characters are rejected-by-sanitization rather than quoted.
fn uci_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Section references may also be anonymous (`@dnsmasq[0]`) — still bare
/// in renders, still shell-word-safe by construction.
fn uci_section_ref(section: &str) -> String {
    section
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '[' | ']') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// UCI identifier tokens (section names, section types, service names)
/// render bare when they match the safe charset — the 1.x convention
/// (`uci set network.wg0=interface`, `/etc/init.d/network restart`), so
/// golden output is byte-identical to the Python builders. Anything
/// outside the charset is single-quoted instead: a hostile name can
/// splice shell syntax neither bare nor quoted.
fn uci_token(token: &str) -> String {
    let safe = !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'));
    if safe {
        token.to_string()
    } else {
        shell_quote(token)
    }
}

/// Render a plan to a POSIX shell script (BusyBox `ash`-compatible — the
/// OpenWrt shell transport, matching 1.x's `render_shell` conventions:
/// single-quoted uci values, `/etc/init.d/<name> <action>`).
///
/// The whole plan renders as **one script** so device-resolution state
/// (`ResolveNetworkDevice` → `UciValue::ResolvedDevice`) survives within a
/// single remote shell. Run it with `set -e`; verification is separate and
/// read-only (see `Plan::verification`).
#[must_use]
pub fn render_shell(plan: &Plan) -> String {
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str(&format!(
        "# conwrt plan: {} -> model {}\n",
        plan.profile_id, plan.model_id
    ));
    script.push_str("set -e\n\n");

    for op in &plan.ops {
        match op {
            PlanOp::EnsurePackage { name } => {
                script.push_str(&format!("# install package {name}\n"));
                script.push_str(&format!(
                    "opkg install {} 2>/dev/null || apk add {}\n\n",
                    shell_quote(name),
                    shell_quote(name)
                ));
            }
            PlanOp::RevertUci { config } => {
                script.push_str(&format!("# revert staged {config} baseline\n"));
                // `|| true`: on a fresh install the config file may not
                // exist yet; reverting nothing must not abort the script.
                script.push_str(&format!("uci -q revert {config} 2>/dev/null || true\n\n"));
            }
            PlanOp::ClearUciSections {
                config,
                section_type,
            } => {
                script.push_str(&format!("# clear {config}.{section_type} sections\n"));
                script.push_str(&format!(
                    "for _s in $(uci -q show {config} 2>/dev/null | grep '={section_type}' \
                     | cut -d. -f2 | cut -d= -f1); do uci -q delete {config}.$_s; done\ntrue\n\n"
                ));
            }
            PlanOp::ResolveNetworkDevice { network } => {
                let var = device_var(network);
                script.push_str(&format!("# resolve device for network {network}\n"));
                script.push_str(&format!(
                    // `|| true`: under `set -e`, a failed command
                    // substitution in an assignment aborts the script —
                    // and `uci get` exits 1 when the option is absent
                    // (which is this branch's whole purpose).
                    "{var}=$(uci get network.{network}.device 2>/dev/null || true)\n\
                     if [ -z \"${var}\" ] || ! ip addr show \"${var}\" 2>/dev/null \
                     | grep -q \"inet \"; then\n\
                     \x20 {var}=$(ip route show default 0.0.0.0/0 2>/dev/null \
                     | awk '{{print $5}}' | head -1)\n\
                     fi\n\
                     if [ -z \"${var}\" ]; then {var}={network}; fi\n\n"
                ));
            }
            PlanOp::SetUciSection {
                config,
                section,
                section_type,
                options,
            } => {
                script.push_str(&format!("# uci {config}.{section}={section_type}\n"));
                script.push_str(&format!(
                    "uci set {config}.{}={}\n",
                    uci_token(section),
                    uci_token(section_type)
                ));
                for (option, value) in options {
                    match value {
                        UciValue::Literal(v) => script.push_str(&format!(
                            "uci set {config}.{section}.{}={}\n",
                            uci_key(option),
                            shell_quote(v)
                        )),
                        UciValue::ResolvedDevice { network } => {
                            let var = device_var(network);
                            script.push_str(&format!(
                                "uci set {config}.{section}.{}=\"${var}\"\n",
                                uci_key(option)
                            ));
                        }
                    }
                }
                script.push('\n');
            }
            PlanOp::SetUciOptions {
                config,
                section,
                options,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!("# uci {config}.{section} options\n"));
                for (option, value) in options {
                    match value {
                        UciValue::Literal(v) => script.push_str(&format!(
                            "uci set {config}.{section}.{}={}\n",
                            uci_key(option),
                            shell_quote(v)
                        )),
                        UciValue::ResolvedDevice { network } => {
                            let var = device_var(network);
                            script.push_str(&format!(
                                "uci set {config}.{section}.{}=\"${var}\"\n",
                                uci_key(option)
                            ));
                        }
                    }
                }
                script.push('\n');
            }
            PlanOp::UciDeleteOption {
                config,
                section,
                option,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!(
                    "# uci delete {config}.{section}.{}\nuci -q delete {config}.{section}.{} \
|| true\n\n",
                    uci_key(option),
                    uci_key(option)
                ));
            }
            PlanOp::UciAddList {
                config,
                section,
                option,
                value,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!(
                    "# uci add_list {config}.{section}.{}\nuci add_list {config}.{section}.{}={}\n\n",
                    uci_key(option),
                    uci_key(option),
                    shell_quote(value)
                ));
            }
            PlanOp::ResetUciConfig { config } => {
                script.push_str(&format!(
                    "# reset uci {config}\nuci -q delete {config} >/dev/null 2>&1 || true\n\n"
                ));
            }
            PlanOp::CleanupUciSections { config, pattern } => {
                // Byte-exact port of 1.x `uci_cleanup_sections_sh`
                // (scripts/profile/uci_helpers.py) — golden-compared in
                // tests/use_case_goldens.rs.
                script.push_str(&format!(
                    "# cleanup uci {config} sections matching {pattern}\n"
                ));
                script.push_str(&format!(
                    "while uci show {config} 2>/dev/null | grep -q \"{pattern}\"; do \
                     _s=$(uci show {config} 2>/dev/null | grep \"{pattern}\" \
                     | head -1 | cut -d. -f2 | cut -d= -f1); \
                     uci delete \"{config}.$_s\" 2>/dev/null; done; true\n\n"
                ));
            }
            PlanOp::Shell { command } => {
                // No trailing blank line: heredoc payloads (tether's ADB
                // hotplug hook) require exact line adjacency — a blank line
                // between `cat << EOF` and the body would corrupt the file.
                script.push_str(&format!("{command}\n"));
            }
            PlanOp::CommitUci { config } => {
                script.push_str(&format!("# uci commit {config}\nuci commit {config}\n\n"));
            }
            PlanOp::Service { name, action } => {
                let action = match action {
                    ServiceAction::Enable => "enable",
                    ServiceAction::Restart => "restart",
                };
                script.push_str(&format!(
                    "# service {name} {action}\n/etc/init.d/{} {}\n\n",
                    uci_token(name),
                    action
                ));
            }
        }
    }
    script
}

fn plan_sqm(model: &DeviceModel, sqm: &SqmProfile) -> Result<Plan, Unsupported> {
    sqm.validate()?;
    let iface = &sqm.interface;
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "sqm-scripts".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-sqm".into(),
        },
        // Clean baseline first: an aborted earlier session can leave
        // staged changes in /tmp/.uci that the commit below would
        // otherwise make permanent (AGENTS.md uci-revert rule).
        PlanOp::RevertUci {
            config: "sqm".into(),
        },
        PlanOp::ClearUciSections {
            config: "sqm".into(),
            section_type: "queue".into(),
        },
        PlanOp::ResolveNetworkDevice {
            network: iface.clone(),
        },
        PlanOp::SetUciSection {
            config: "sqm".into(),
            section: iface.clone(),
            section_type: "queue".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                // actual device, not the UCI network name (1.x lesson)
                (
                    "interface".into(),
                    UciValue::ResolvedDevice {
                        network: iface.clone(),
                    },
                ),
                ("script".into(), literal(sqm.script.clone())),
                ("qdisc".into(), literal(sqm.qdisc.clone())),
                ("linklayer".into(), literal(sqm.link_layer.clone())),
                ("overhead".into(), literal(sqm.overhead.to_string())),
                ("download".into(), literal(sqm.download_kbps.to_string())),
                ("upload".into(), literal(sqm.upload_kbps.to_string())),
                (
                    "linklayer_adaptation_mechanism".into(),
                    literal("default".into()),
                ),
                ("debug_logging".into(), literal("0".into())),
                ("verbosity".into(), literal("5".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "sqm".into(),
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Restart,
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "shaper rates persisted".into(),
            command: format!("uci -q get sqm.{iface}.download"),
            expect_contains: sqm.download_kbps.to_string(),
        },
        VerificationCheck {
            description: "qdisc active on the device".into(),
            command: "tc qdisc show".into(),
            expect_contains: sqm.qdisc.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/sqm enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "sqm".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_with_capabilities(caps: Option<Vec<String>>) -> DeviceModel {
        let caps_json = caps.map(|c| {
            let list: Vec<String> = c.iter().map(|c| format!("\"{c}\"")).collect();
            format!(", \"capabilities\": [{}]", list.join(", "))
        });
        let json = format!(
            "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"24\"}},\
              \"mac_oui\":[]{}}}",
            caps_json.unwrap_or_default()
        );
        serde_json::from_str(&json).expect("fixture model parses")
    }

    fn sqm() -> SqmProfile {
        SqmProfile {
            download_kbps: 340_000,
            upload_kbps: 19_000,
            interface: "wan".into(),
            qdisc: "cake".into(),
            script: "piece_of_cake.qos".into(),
            link_layer: "none".into(),
            overhead: 0,
        }
    }

    #[test]
    fn capabilities_gate_rejects_missing_tag() {
        let model = model_with_capabilities(Some(vec!["ethernet".into()]));
        assert!(capabilities_satisfied(&model, &["usb"]).is_err());
        let full = model_with_capabilities(Some(vec!["ethernet".into(), "usb".into()]));
        assert!(capabilities_satisfied(&full, &["usb"]).is_ok());
        let none = model_with_capabilities(None);
        assert!(capabilities_satisfied(&none, &[]).is_ok());
    }

    #[test]
    fn param_bounds_match_1x() {
        assert!(sqm().validate().is_ok());
        assert!(matches!(
            SqmProfile {
                download_kbps: 0,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                upload_kbps: 0,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                overhead: 513,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                interface: "eth0; rm -rf /".into(),
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn render_shell_matches_1x_conventions() {
        let model = model_with_capabilities(None);
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Sqm(SqmProfile {
                download_kbps: 340_000,
                upload_kbps: 19_000,
                ..test_sqm_defaults()
            }),
        )
        .expect("plans");
        let script = render_shell(&plan);
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("set -e"));
        // package install covers both package managers
        assert!(script.contains("opkg install 'sqm-scripts' 2>/dev/null || apk add 'sqm-scripts'"));
        // clear-sections idiom, 1.x style
        assert!(script.contains("uci -q show sqm 2>/dev/null | grep '=queue'"));
        // device resolution sets the var the section later references
        assert!(
            script.contains("_conwrt_dev_wan=$(uci get network.wan.device 2>/dev/null || true)")
        );
        assert!(script.contains("uci set sqm.wan.interface=\"$_conwrt_dev_wan\""));
        // single-quoted literals, 1.x convention
        assert!(script.contains("uci set sqm.wan.download='340000'"));
        assert!(script.contains("uci set sqm.wan.upload='19000'"));
        assert!(script.contains("uci commit sqm"));
        assert!(script.contains("/etc/init.d/sqm enable"));
        assert!(script.contains("/etc/init.d/sqm restart"));
    }

    #[test]
    fn render_shell_quotes_hostile_literals() {
        let model = model_with_capabilities(None);
        let mut sqm = test_sqm_defaults();
        sqm.script = "evil'; rm -rf /; '".into();
        let plan = plan_profile(&DeviceState::OpenWrt, &model, &Profile::Sqm(sqm)).expect("plans");
        let script = render_shell(&plan);
        assert!(
            script.contains("uci set sqm.wan.script='evil'\\''; rm -rf /; '\\'''"),
            "single quotes must be escaped, not interpolated: {script}"
        );
    }

    #[test]
    fn sqm_plan_reverts_staged_baseline_before_first_mutation() {
        let model = model_with_capabilities(None);
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Sqm(test_sqm_defaults()),
        )
        .expect("plans");
        let script = render_shell(&plan);
        let revert_pos = script
            .find("uci -q revert sqm")
            .expect("script must revert the sqm baseline");
        let first_mutation = script
            .find("uci -q show sqm")
            .or_else(|| script.find("uci set sqm"))
            .expect("script mutates sqm");
        assert!(
            revert_pos < first_mutation,
            "revert must precede the first sqm mutation:\n{script}"
        );
    }

    fn test_sqm_defaults() -> SqmProfile {
        SqmProfile {
            download_kbps: 10_000,
            upload_kbps: 5_000,
            interface: "wan".into(),
            qdisc: "cake".into(),
            script: "piece_of_cake.qos".into(),
            link_layer: "none".into(),
            overhead: 0,
        }
    }

    // ---- tether / wireguard-client / guest-wifi ports (parity §4) ----

    fn wireguard() -> WireguardClientProfile {
        WireguardClientProfile {
            peer_public_key: "SERVERKEY".into(),
            endpoint_host: "vpn.example.com".into(),
            ..WireguardClientProfile::default()
        }
    }

    fn plan_for(profile: Profile) -> Plan {
        let caps = profile.requires().first().map(|cap| vec![(**cap).into()]);
        plan_profile(
            &DeviceState::OpenWrt,
            &model_with_capabilities(caps),
            &profile,
        )
        .expect("plans")
    }

    #[test]
    fn wireguard_param_bounds_match_1x_validators() {
        assert!(wireguard().validate().is_ok());
        // validate_host: empty, junk, embedded shell metacharacters
        assert!(matches!(
            WireguardClientProfile {
                endpoint_host: String::new(),
                ..wireguard()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            WireguardClientProfile {
                endpoint_host: "vpn; rm -rf /".into(),
                ..wireguard()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            WireguardClientProfile {
                endpoint_host: "-leadingdash.example.com".into(),
                ..wireguard()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // validate_port bounds (1-65535)
        assert!(matches!(
            WireguardClientProfile {
                endpoint_port: 0,
                ..wireguard()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // registry required-param gate: peer_public_key
        assert!(matches!(
            WireguardClientProfile {
                peer_public_key: String::new(),
                ..wireguard()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // IPv4 endpoints are first-class hosts (1.x _IPV4_RE branch)
        assert!(
            WireguardClientProfile {
                endpoint_host: "10.0.0.1".into(),
                ..wireguard()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn wireguard_kill_switch_branches_match_1x() {
        let on = render_shell(&plan_for(Profile::WireguardClient(wireguard())));
        assert!(on.contains("wg_client_killswitch.name='KillSwitch-Reject-NonVPN'"));
        assert!(on.contains("wg show wg0"));
        assert!(on.contains("uci delete firewall.wg_client_killswitch"));
        assert!(on.contains("fw4 restart"));

        let off = render_shell(&plan_for(Profile::WireguardClient(
            WireguardClientProfile {
                kill_switch: false,
                ..wireguard()
            },
        )));
        assert!(!off.contains("wg_client_killswitch"));
        assert!(!off.contains("wg show wg0"));
    }

    #[test]
    fn wireguard_dns_and_psk_branches_match_1x() {
        let dns = render_shell(&plan_for(Profile::WireguardClient(
            WireguardClientProfile {
                dns: "9.9.9.9".into(),
                ..wireguard()
            },
        )));
        assert!(dns.contains("uci add_list network.wg0.dns='9.9.9.9'"));

        let no_dns = render_shell(&plan_for(Profile::WireguardClient(
            WireguardClientProfile {
                dns: String::new(),
                ..wireguard()
            },
        )));
        assert!(!no_dns.contains("uci add_list"));

        let psk = render_shell(&plan_for(Profile::WireguardClient(
            WireguardClientProfile {
                peer_psk: "my-secret-psk".into(),
                ..wireguard()
            },
        )));
        assert!(psk.contains("uci set network.wg0_peer.preshared_key='my-secret-psk'"));
    }

    #[test]
    fn wireguard_firewall_cleanup_uses_1x_while_loop_shape() {
        let script = render_shell(&plan_for(Profile::WireguardClient(wireguard())));
        assert!(script.contains(
            "while uci show firewall 2>/dev/null | grep -q \"name='vpn'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='vpn'\" \
             | head -1 | cut -d. -f2 | cut -d= -f1); \
             uci delete \"firewall.$_s\" 2>/dev/null; done; true"
        ));
        assert!(script.contains("uci set firewall.wg_client_vpn.name='vpn'"));
        assert!(script.contains("uci set firewall.wg_client_fwd.dest='vpn'"));
        assert!(script.contains("echo 'WireGuard client configured: vpn.example.com:51820'"));
    }

    #[test]
    fn wireguard_server_default_render_matches_1x_shape() {
        let script = render_shell(&plan_for(Profile::WireguardServer(
            WireguardServerProfile {
                private_key: "test_key_12345".into(),
                ..WireguardServerProfile::default()
            },
        )));
        assert!(script.contains("uci set network.wg0=interface"));
        assert!(script.contains("uci set network.wg0.proto='wireguard'"));
        assert!(script.contains("uci set network.wg0.private_key='test_key_12345'"));
        assert!(script.contains("uci set network.wg0.listen_port='51820'"));
        assert!(script.contains("uci add_list network.wg0.addresses='10.1.99.1/24'"));
        assert!(script.contains(
            "mkdir -p /etc/wireguard && \
                             wg show wg0 public-key > /etc/wireguard/server_public_key \
                             2>/dev/null || true"
        ));
        assert!(script.contains("uci commit network"));
        assert!(script.contains("uci commit firewall"));
        assert!(
            !script.contains("wg0_peer1"),
            "no peer by default (1.x branch)"
        );
    }

    #[test]
    fn wireguard_server_custom_params_match_1x_shape() {
        let script = render_shell(&plan_for(Profile::WireguardServer(
            WireguardServerProfile {
                private_key: "abc123".into(),
                listen_port: 12_345,
                subnet: "172.16.0.1/16".into(),
                ..WireguardServerProfile::default()
            },
        )));
        assert!(script.contains("uci set network.wg0.listen_port='12345'"));
        assert!(script.contains("uci add_list network.wg0.addresses='172.16.0.1/16'"));
        assert!(script.contains("uci set firewall.wg_server_allow.dest_port='12345'"));
        assert!(
            script
                .contains("echo \"WireGuard server configured: port 12345, subnet 172.16.0.1/16\"")
        );
    }

    #[test]
    fn wireguard_server_peer_and_psk_branches_match_1x() {
        let with_peer = render_shell(&plan_for(Profile::WireguardServer(
            WireguardServerProfile {
                private_key: "server_key".into(),
                peer1_public_key: "peer_pub_key".into(),
                peer1_allowed_ips: "10.1.99.2/32".into(),
                ..WireguardServerProfile::default()
            },
        )));
        assert!(with_peer.contains("uci set network.wg0_peer1=wireguard_wg0"));
        assert!(with_peer.contains("uci set network.wg0_peer1.public_key='peer_pub_key'"));
        assert!(with_peer.contains("uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'"));
        assert!(with_peer.contains("uci set network.wg0_peer1.route_allowed_ips='1'"));
        assert!(!with_peer.contains("preshared_key"));

        let with_psk = render_shell(&plan_for(Profile::WireguardServer(
            WireguardServerProfile {
                private_key: "server_key".into(),
                peer1_public_key: "peer_pub_key".into(),
                peer1_psk: "shared_secret_key".into(),
                ..WireguardServerProfile::default()
            },
        )));
        assert!(with_psk.contains("uci set network.wg0_peer1.preshared_key='shared_secret_key'"));
        assert!(
            with_psk
                .find("route_allowed_ips")
                .zip(with_psk.find("preshared_key"))
                .is_some_and(|(route, psk)| route < psk),
            "psk renders last (1.x dict insertion order)"
        );
    }

    #[test]
    fn wireguard_server_firewall_sections_match_1x_shape() {
        let script = render_shell(&plan_for(Profile::WireguardServer(
            WireguardServerProfile::default(),
        )));
        assert!(script.contains(
            "while uci show firewall 2>/dev/null | grep -q \"name='Allow-WireGuard'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='Allow-WireGuard'\" \
             | head -1 | cut -d. -f2 | cut -d= -f1); \
             uci delete \"firewall.$_s\" 2>/dev/null; done; true"
        ));
        assert!(script.contains("uci set firewall.wg_server_vpn.name='vpn'"));
        assert!(script.contains("uci set firewall.wg_server_vpn.input='ACCEPT'"));
        assert!(script.contains("uci set firewall.wg_server_fwd_lan.dest='lan'"));
        assert!(script.contains("uci set firewall.wg_server_fwd_wan.dest='wan'"));
        assert!(script.contains("uci set firewall.wg_server_allow.src='wan'"));
        assert!(script.contains("uci set firewall.wg_server_allow.proto='udp'"));
        assert!(script.contains("/etc/init.d/network restart"));
    }

    #[test]
    fn tether_param_bounds_and_capability_gate() {
        assert!(TetherProfile::default().validate().is_ok());
        assert!(matches!(
            TetherProfile {
                interface: "eth0; rm -rf /".into(),
                ..TetherProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            TetherProfile {
                detect_timeout_secs: 0,
                ..TetherProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // requires usb — a model without it is refused before any op
        let refusal = plan_profile(
            &DeviceState::OpenWrt,
            &model_with_capabilities(None),
            &Profile::Tether(TetherProfile::default()),
        )
        .expect_err("must refuse");
        assert!(matches!(
            refusal,
            Unsupported::MissingCapability {
                capability: ref c,
                ..
            } if c == "usb"
        ));
    }

    #[test]
    fn tether_variant_scripts_and_packages() {
        for (variant, golden_id) in [
            (TetherVariant::Auto, "tether"),
            (TetherVariant::Android, "tether-android"),
            (TetherVariant::AndroidAdb, "tether-android-adb"),
            (TetherVariant::Ios, "tether-ios"),
        ] {
            let plan = plan_for(Profile::Tether(TetherProfile {
                variant,
                ..TetherProfile::default()
            }));
            assert_eq!(plan.profile_id, golden_id);
            let script = render_shell(&plan);
            assert!(script.contains("for _ in $(seq 1 45); do"));
            let wants_usbmuxd = matches!(variant, TetherVariant::Auto | TetherVariant::Ios);
            assert_eq!(
                script.contains("/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &"),
                wants_usbmuxd
            );
            let wants_adb = matches!(variant, TetherVariant::Auto | TetherVariant::AndroidAdb);
            assert_eq!(
                script.contains("99-usb-tether-adb << 'HOTPLUG_EOF'"),
                wants_adb
            );
            assert_eq!(
                script.contains("adb"),
                wants_adb || variant == TetherVariant::Auto
            );
            // Android detection drivers vs iOS ipheth
            match variant {
                TetherVariant::Android | TetherVariant::AndroidAdb => {
                    assert!(script.contains("rndis\\|cdc_ether"));
                    assert!(!script.contains("ipheth"));
                }
                TetherVariant::Ios => {
                    assert!(script.contains("ipheth"));
                    assert!(script.contains("apple\\|iphone"));
                }
                TetherVariant::Auto => {
                    assert!(script.contains("usbnet\\|ipheth"));
                    assert!(script.contains("apple\\|iphone"));
                }
            }
            let pkg_count = plan
                .ops
                .iter()
                .filter(|op| matches!(op, PlanOp::EnsurePackage { .. }))
                .count();
            assert_eq!(pkg_count, variant.packages().len());
        }
    }

    #[test]
    fn tether_heredoc_reassembles_adjacently() {
        let plan = plan_for(Profile::Tether(TetherProfile::default()));
        let script = render_shell(&plan);
        // The heredoc body must follow the cat line immediately (byte
        // adjacency — no comment or blank line in between).
        let lines: Vec<&str> = script.lines().collect();
        let cat_at = lines
            .iter()
            .position(|l| l.contains("<< 'HOTPLUG_EOF'"))
            .expect("heredoc opener");
        assert_eq!(
            lines[cat_at + 1],
            "[ \"$ACTION\" = \"bind\" ] || exit 0",
            "heredoc body must start on the next line"
        );
        let eof_at = lines
            .iter()
            .position(|l| *l == "HOTPLUG_EOF")
            .expect("heredoc terminator");
        assert!(lines[..eof_at].iter().any(|l| l.contains(") &")));
    }

    #[test]
    fn guest_wifi_param_bounds_match_1x_validators() {
        assert!(GuestWifiProfile::default().validate().is_ok());
        // validate_ssid: empty, >32 bytes, control characters
        for bad in [
            GuestWifiProfile {
                ssid: String::new(),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                ssid: "x".repeat(33),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                ssid: "bad\u{1}ssid".into(),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                key: "line\nbreak".into(),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                encryption: "wep".into(),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                band: "2.4".into(),
                ..GuestWifiProfile::default()
            },
            GuestWifiProfile {
                network_name: "guest net".into(),
                ..GuestWifiProfile::default()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
                "{bad:?} must be rejected"
            );
        }
        // capability gate: wifi
        let refusal = plan_profile(
            &DeviceState::OpenWrt,
            &model_with_capabilities(None),
            &Profile::GuestWifi(GuestWifiProfile::default()),
        )
        .expect_err("must refuse");
        assert!(matches!(
            refusal,
            Unsupported::MissingCapability {
                capability: ref c,
                ..
            } if c == "wifi"
        ));
    }

    #[test]
    fn guest_wifi_key_branch_and_custom_params_render_1x_shapes() {
        let with_key = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile {
            ssid: "Cafe".into(),
            key: "cafe-pass".into(),
            encryption: "psk-mixed".into(),
            band: "5ghz".into(),
            isolation: false,
            network_name: "voyeurs".into(),
        })));
        assert!(with_key.contains("uci set wireless.guest_ap.key='cafe-pass'"));
        assert!(with_key.contains("uci set wireless.guest_ap.encryption=psk-mixed"));
        assert!(with_key.contains("\"5g\""));
        assert!(with_key.contains("uci set wireless.guest_ap.isolate=0"));
        assert!(with_key.contains("uci set network.voyeurs.ipaddr=\"$_guest_prefix.1\""));
        assert!(with_key.contains("uci set firewall.voyeurs_dns.name='Allow-DNS-voyeurs'"));

        let open = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile::default())));
        assert!(!open.contains("guest_ap.key="));
        assert!(open.contains("uci set wireless.guest_ap.isolate=1"));
    }

    #[test]
    fn hostile_values_are_quoted_not_interpolated() {
        // The shell-op escape hatch must never let a hostile value break
        // out of its quoting (1.x sh_quote behavior at render time).
        let script = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile {
            ssid: "evil'; rm -rf /; '".into(),
            ..GuestWifiProfile::default()
        })));
        assert!(
            script.contains("uci set wireless.guest_ap.ssid='evil'\\''; rm -rf /; '\\''"),
            "ssid must be single-quote escaped: {script}"
        );
        // uci section names derived from user input stay identifier-safe
        let script = render_shell(&plan_for(Profile::WireguardClient(
            WireguardClientProfile {
                private_key: "k'; dropbear off".into(),
                ..wireguard()
            },
        )));
        assert!(script.contains("uci set network.wg0.private_key='k'\\''; dropbear off'"));
    }
}
