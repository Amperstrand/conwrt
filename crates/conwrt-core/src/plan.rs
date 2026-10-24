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
        if self.listen_port == 0 {
            // Port 0 would commit dnsmasq to `127.0.0.1#0` — not a usable
            // DNS destination — and take down LAN name resolution.
            return Err(Unsupported::InvalidParams(
                "listen_port must be > 0: 0 is not a usable DNS destination".into(),
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

/// Dropbear SSH hardening — port of the tested 1.x `ssh-hardening`
/// preset (`scripts/use_cases/ssh_hardening.py`): key-only auth, idle
/// disconnect timeout, auth-try limit, alternate port, GatewayPorts
/// restricted to loopback binding. Every option lands on the anonymous `@dropbear[0]`
/// section; the bool→UCI string coercions are the whole of the logic.
/// No 1.x validators to mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHardeningProfile {
    /// Disable password auth — drives BOTH `PasswordAuth` and
    /// `RootPasswordAuth` (1.x default on).
    pub disable_password_auth: bool,
    /// Idle disconnect timeout in seconds (1.x default 300).
    pub idle_timeout: u32,
    /// Max authentication attempts per connection (1.x default 3).
    pub max_auth_tries: u32,
    /// SSH listen port (1.x default 22).
    pub port: u16,
    /// Restrict GatewayPorts to loopback binding — rendered as
    /// `GatewayPorts='no'` (1.x naming parity). Note the semantics:
    /// GatewayPorts only stops forwarded ports binding non-loopback
    /// addresses; it does NOT disable `-R` remote forwarding. Renamed
    /// from `disable_gateway_ports` for honest semantics (#426, landed
    /// in both implementations).
    pub restrict_gateway_ports: bool,
}

impl Default for SshHardeningProfile {
    fn default() -> Self {
        Self {
            disable_password_auth: true,
            idle_timeout: 300,
            max_auth_tries: 3,
            port: 22,
            restrict_gateway_ports: true,
        }
    }
}

/// Travel-router auto-connect — port of the tested 1.x `travelmate`
/// preset (`scripts/use_cases/travelmate.py`). Travelmate scans the
/// declared radio for upstream APs, joins per its own uplink rules, and
/// handles captive portals. This plan only shapes the daemon's global
/// section — which SSIDs to join is travelmate/wireless config the
/// operator (or a companion profile) manages. No 1.x validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TravelmateProfile {
    /// WiFi radio used for upstream scanning (1.x default `radio0`).
    pub radio: String,
    /// Overall retry timeout in seconds (1.x default 60).
    pub timeout: u32,
    /// Retry count to find a suitable uplink (1.x default 5).
    pub retry: u32,
    /// Enable captive portal detection (1.x default on).
    pub captive: bool,
    /// Known-network seeding (2.x-first capability, beyond the 1.x
    /// preset): STA uplink profiles derived from the deploying host's
    /// saved WiFis. Empty (default) keeps the render 1.x-identical.
    pub uplinks: Vec<WifiUplink>,
}

impl Default for TravelmateProfile {
    fn default() -> Self {
        Self {
            radio: "radio0".into(),
            timeout: 60,
            retry: 5,
            captive: true,
            uplinks: Vec::new(),
        }
    }
}

/// Network-wide ad blocking via AdGuard Home — port of the tested 1.x
/// `adguard` preset (`scripts/use_cases/adguard.py`). The daemon owns
/// its YAML config; this plan only shapes the uci wrapper (listen
/// address, ports), enables + starts it, and points dnsmasq at the
/// local AdGuard DNS instance (noresolv + server=127.0.0.1#port).
/// Web-UI first-run setup (admin account) remains manual — 1.x marks
/// the preset "post-flash setup". No 1.x validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdguardProfile {
    /// Web UI listen address (1.x default `0.0.0.0`).
    pub listen_ip: String,
    /// Web UI port (1.x default 3000).
    pub web_port: u16,
    /// DNS listen port (1.x default 5353, off 53 to avoid the
    /// dnsmasq conflict).
    pub dns_port: u16,
}

impl Default for AdguardProfile {
    fn default() -> Self {
        Self {
            listen_ip: "0.0.0.0".into(),
            web_port: 3000,
            dns_port: 5353,
        }
    }
}

/// Automated 802.11s mesh networking — port of the tested 1.x
/// `mesh11sd` preset (`scripts/use_cases/mesh11sd.py`). The plan swaps
/// wpad-basic for full wpad (verbatim 1.x shell, opkg-era commands
/// kept for parity — they no-op on apk systems), then shapes the
/// daemon's `setup` section. Option order matters for byte parity:
/// `mesh_gate_key` lands BETWEEN `mesh_gate_encryption` and
/// `auto_config` (1.x dict insertion order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mesh11sdProfile {
    /// Unique mesh network ID, required — must match on all nodes
    /// (1.x required-param gate).
    pub mesh_id: String,
    /// Base SSID for the mesh gate AP (1.x default `MeshNet`).
    pub ssid: String,
    /// Mesh gate encryption: `0`=none, `1`=wpa3, `2`=wpa2, `3`=mixed
    /// (1.x default `1`; kept a string for parity).
    pub encryption: String,
    /// WiFi key for the mesh gate AP (empty = none).
    pub key: String,
    /// Auto-config mode: `0`=disabled, `1`=auto, `2`=auto+commit
    /// (1.x default `0`).
    pub auto_config: String,
}

impl Default for Mesh11sdProfile {
    fn default() -> Self {
        Self {
            mesh_id: String::new(),
            ssid: "MeshNet".into(),
            encryption: "1".into(),
            key: String::new(),
            auto_config: "0".into(),
        }
    }
}

impl Mesh11sdProfile {
    /// 1.x has exactly one gate: `mesh_id` is a required param.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.mesh_id.is_empty() {
            return Err(Unsupported::InvalidParams(
                "mesh_id is required (must match on all mesh nodes)".into(),
            ));
        }
        Ok(())
    }
}

/// Self-healing reboot for bench/lab devices — port of the 1.x
/// `rescue-watchdog` preset (`scripts/use_cases/rescue_watchdog.py`,
/// born from the 2026-10-08 x1860 wedges: kernel-level networking
/// death that only a hands-on power cycle cured). The whole plan is
/// ONE verbatim shell payload: procd init + watchdog loop heredocs,
/// pinging the management target once a minute and force-rebooting
/// after 3 consecutive failures (10-minute boot grace). 1.x marks it
/// untested — verify grace/reboot on hardware before trusting
/// unattended. No packages, no validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RescueWatchdogProfile {
    /// Management IP pinged once a minute (bench host LAN address;
    /// 1.x default `192.168.1.254`).
    pub target: String,
}

impl Default for RescueWatchdogProfile {
    fn default() -> Self {
        Self {
            target: "192.168.1.254".into(),
        }
    }
}

/// Multi-WAN failover / load balancing — port of the tested 1.x
/// `mwan3` preset (`scripts/use_cases/mwan3.py`, verified on 24.10.2
/// with the iptables-nft compat layer in QEMU). Two tracked WAN
/// interfaces, one member each (metric/weight per policy), a
/// `<primary>_policy` using both members, and default_v4 + sticky-HTTPS
/// rules. 1.x renders the track IPs as bare `list track_ip 'IP'`
/// lines — broken shell that no-`set -e` 1.x silently ignored; this
/// port renders real `uci add_list` ops (the golden comparator
/// excludes track-ip wiring from both sides and the unit tests pin the
/// corrected lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mwan3Profile {
    /// Primary WAN UCI interface name (1.x `interface_name` charset).
    pub primary: String,
    /// Secondary WAN UCI interface name (e.g. `usbwan` from tethering).
    pub secondary: String,
    /// `failover` (secondary metric 2) or `balanced` (equal metrics,
    /// weight 2:1) — 1.x treats any other value as failover.
    pub policy: String,
    /// IPs pinged for connectivity tracking (1.x default: four public
    /// resolvers).
    pub track_ips: Vec<String>,
}

impl Default for Mwan3Profile {
    fn default() -> Self {
        Self {
            primary: "wan".into(),
            secondary: "usbwan".into(),
            policy: "failover".into(),
            track_ips: vec![
                "1.0.0.1".into(),
                "1.1.1.1".into(),
                "8.8.8.8".into(),
                "8.8.4.4".into(),
            ],
        }
    }
}

impl Mwan3Profile {
    /// 1.x `shell_safe::interface_name` parity: non-empty, `[A-Za-z0-9_.:-]+`.
    /// `policy` additionally carries a shell-safe charset — it is the one
    /// value this plan interpolates into a raw `echo` line, and 1.x never
    /// validated it (the PlanOp::Shell contract requires gated values).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.primary) {
            return Err(Unsupported::InvalidParams(
                "primary contains unsafe characters".into(),
            ));
        }
        if !iface_ok(&self.secondary) {
            return Err(Unsupported::InvalidParams(
                "secondary contains unsafe characters".into(),
            ));
        }
        if !self
            .policy
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(Unsupported::InvalidParams(
                "policy contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// nftables-native policy-based routing — port of the tested 1.x `pbr`
/// preset (`scripts/use_cases/pbr.py`, verified on OpenWrt 24.10.2 in
/// QEMU/KVM). pbr is the fw4-native successor to mwan3's iptables
/// marking: this plan enables the service with fw4 include-file mode,
/// pins the default WAN interface for policy routing, and registers
/// the LAN as a local interface. pbr does NOT do multi-WAN load
/// balancing on its own (mwan4 integration arrives with mwan4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbrProfile {
    /// WAN UCI interface used for default routing (1.x default `wan`).
    pub wan_interface: String,
    /// LAN interface counted as local traffic (1.x default `lan`).
    pub lan_interface: String,
    /// Drop traffic that matches no policy (1.x default on).
    pub strict_enforcement: bool,
}

impl Default for PbrProfile {
    fn default() -> Self {
        Self {
            wan_interface: "wan".into(),
            lan_interface: "lan".into(),
            strict_enforcement: true,
        }
    }
}

impl PbrProfile {
    /// 1.x interpolated `wan_interface`/`lan_interface` UNQUOTED into
    /// two shell lines (`netifd_interface_default=`, `add_list …
    /// netifd_interface_local=`) — a command-injection hole for
    /// hostile param values. The port gates both with the 1.x
    /// `shell_safe::interface_name` charset (`[A-Za-z0-9_.:-]+`); the
    /// same gate landed Python-side with this port (mwan3/#448
    /// precedent). Valid input renders byte-identically.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.wan_interface) {
            return Err(Unsupported::InvalidParams(
                "wan_interface contains unsafe characters".into(),
            ));
        }
        if !iface_ok(&self.lan_interface) {
            return Err(Unsupported::InvalidParams(
                "lan_interface contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// Transparent proxy via Clash/Mihomo — port of the 1.x `openclash`
/// preset (`scripts/use_cases/openclash.py`, ops characterization +
/// transport parity). The plan types ONLY the flash-time config: the
/// package set, the config dir, the `openclash.config` uci section
/// (proxy/core/dashboard/DNS mode), and service enable. The proxy
/// cannot run without a subscription config, which is a POST-FLASH
/// step via the LuCI web UI — this plan stops at the same boundary
/// line as 1.x (its closing echo). Package-delivery boundary:
/// `luci-app-openclash` ships from the third-party vernesong feed,
/// NOT official OpenWrt packages (1.x shares this gap — its
/// `packages_via="auto"` list fails to resolve on stock devices and
/// the public ASU alike). The intended delivery is a baked image or a
/// preinstalled device, where the leading `EnsurePackage`
/// short-circuits on `opkg list-installed`; on a stock device the
/// apply aborts loudly at the FIRST op — before any configuration is
/// touched — rather than leaving dangling config for absent software.
/// An acquisition phase (feed setup / release-IPK download) is M7
/// image-pipeline work, not a plan op. The 1.x `packages_remove:
/// [dnsmasq]` (swapped for `dnsmasq-full`) is likewise an image-build
/// directive, but rides the plan as a guarded removal because this
/// plan installs packages at apply time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClashProfile {
    /// Default proxy protocol (1.x default `ss`; vmess/trojan/vless…).
    pub proxy_type: String,
    /// Clash core (1.x default `Meta` = Mihomo; also Dev, Tun).
    pub core_type: String,
    /// DNS mode (1.x default `redir-host`; also fake-ip).
    pub dns_mode: String,
}

impl Default for OpenClashProfile {
    fn default() -> Self {
        Self {
            proxy_type: "ss".into(),
            core_type: "Meta".into(),
            dns_mode: "redir-host".into(),
        }
    }
}

impl OpenClashProfile {
    /// 1.x interpolated `core_type`/`proxy_type` into a DOUBLE-quoted
    /// `echo` line (the uci values ride safe single-quoting, the echo
    /// does not) — a `"`/`$()`/backtick value was a command-injection
    /// hole (the mwan3/#448 class, found by this port). The port
    /// gates all three params with the `[A-Za-z0-9._-]+` token
    /// charset; the same gate landed Python-side (`_token` in
    /// openclash.py `_resolve_params`). Valid input renders
    /// byte-identically.
    pub fn validate(&self) -> Result<(), Unsupported> {
        for (field, value) in [
            ("proxy_type", &self.proxy_type),
            ("core_type", &self.core_type),
            ("dns_mode", &self.dns_mode),
        ] {
            let ok = !value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
            if !ok {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} contains unsafe characters"
                )));
            }
        }
        Ok(())
    }
}

/// Trusted HTTPS certificates for LAN services — port of the tested
/// 1.x `ssl` preset (`scripts/use_cases/ssl.py`, verified on
/// COVR-X1860: cert download + uhttpd config, lancert/qip providers).
/// The flash-time plan types the uhttpd HTTPS wiring (cert/key paths
/// and `listen_https` on :443) and the optional nodogsplash 443
/// pass-through. The certificates themselves are NOT flash-time
/// material: 1.x downloads them HOST-side (lancert.dev / qip.sh) and
/// SCPs them post-flash (`deploy_ssl_post_flash`) — the plan guards
/// the uhttpd wiring on both cert files existing at runtime, so a
/// cert-less router skips it with a loud message instead of pointing
/// uhttpd at missing files (certs expire in 90 days; re-deploy and
/// re-run to renew).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslProfile {
    /// Cert provider — the 1.x ParamDef choice set
    /// (`lancert` per-IP, `qip` wildcard-per-subnet, `manual`
    /// host-supplied files). Labels the config only; the uhttpd /
    /// nodogsplash wiring is provider-independent.
    pub provider: String,
    /// Configure uhttpd to serve HTTPS on port 443 (1.x default on).
    pub enable_uhttpd_https: bool,
    /// Allow unauthenticated clients to reach port 443 through
    /// nodogsplash (1.x default on).
    pub open_port_443_nds: bool,
}

impl Default for SslProfile {
    fn default() -> Self {
        Self {
            provider: "lancert".into(),
            enable_uhttpd_https: true,
            open_port_443_nds: true,
        }
    }
}

impl SslProfile {
    /// 1.x declared `choices=("lancert", "qip", "manual")` on the
    /// provider ParamDef but `_resolve_params` never enforced it —
    /// and the value was interpolated into a rendered comment line,
    /// where a newline injected live shell (mwan3/#448 class, found
    /// by this port). The port enforces the declared choice set; the
    /// same gate landed Python-side (`require_choice` in ssl.py
    /// `_resolve_params`).
    pub fn validate(&self) -> Result<(), Unsupported> {
        if !matches!(self.provider.as_str(), "lancert" | "qip" | "manual") {
            return Err(Unsupported::InvalidParams(
                "provider must be one of: lancert, manual, qip".into(),
            ));
        }
        Ok(())
    }
}

/// Private Internet Access via OpenVPN (tun0) — port of the 1.x
/// `vpn-pia-openvpn` preset (`scripts/use_cases/vpn_providers/pia.py`,
/// the validated static recipe: RSA-4096 CA, UDP 8080 pool +
/// remote-random, IPv6 pull-filters, NO persist-tun). Everything is
/// resolved at BUILD time: the device receives static files (CA +
/// credentials + endpoint pool) and makes no PIA API calls. The
/// WireGuard variant (vpn-pia) is torn down first so the two
/// technologies never fight over the vpn zone. 1.x marks the
/// op-path untested-on-hardware (the recipe itself was validated
/// manually on GL-MT3000 / 25.12.5) — same evidence bar here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPiaOpenvpnProfile {
    /// PIA account username (the p-number). Required: the Rust surface
    /// refuses to plan an unconfigured VPN (1.x image-bakes a comment
    /// stub; `apply` needs real intent).
    pub username: String,
    /// PIA account password. Lands as a literal line inside the
    /// quoted auth heredoc — validate() rejects control characters
    /// (a newline would inject script lines: the mwan3/#448 class).
    pub password: String,
    /// OpenVPN server port (PIA modern default 8080; kept a string
    /// for 1.x parity).
    pub port: String,
    /// Upstream gateway IP; pins the endpoint pool's /32 routes to
    /// the upstream so tunnel traffic never routes via tun (empty =
    /// no route pinning — 1.x parity).
    pub upstream_gateway: String,
    /// Upstream interface name for the route pins (1.x default `wan`).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops (1.x default on;
    /// the verify loop auto-removes it when the tunnel never comes up
    /// so a bad config cannot blackhole the LAN).
    pub kill_switch: bool,
    /// Accept SSH/LuCI (22/80/443) from the VPN zone to the router
    /// (1.x default on — remote management through the exit).
    pub allow_management: bool,
    /// Endpoint pool (default: the validated 10-host US pool).
    pub remotes: Vec<String>,
}

impl Default for VpnPiaOpenvpnProfile {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            port: "8080".into(),
            upstream_gateway: String::new(),
            upstream_iface: "wan".into(),
            kill_switch: true,
            allow_management: true,
            remotes: [
                "151.241.122.99",
                "37.19.197.168",
                "151.241.119.192",
                "37.19.220.37",
                "181.41.206.48",
                "102.129.153.205",
                "145.79.182.176",
                "193.56.117.160",
                "191.96.106.197",
                "173.239.198.91",
            ]
            .iter()
            .map(|s| (*s).into())
            .collect(),
        }
    }
}

impl VpnPiaOpenvpnProfile {
    /// 1.x had no validators on this preset (only non-empty ParamDefs).
    /// The port adds the gates the rendered payload needs: username and
    /// password must be non-empty and free of control characters — they
    /// land as literal lines inside single-quoted heredocs, so a
    /// newline injects script lines (mwan3/#448 class); each remote and
    /// the optional gateway must be dotted-quad IPv4 (they interpolate
    /// into an unquoted `for` token list and an `ip route replace`
    /// line); the interface name rides the 1.x `interface_name`
    /// charset.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let ctrl = |v: &str| v.chars().any(|c| c.is_ascii_control());
        if self.username.is_empty() {
            return Err(Unsupported::InvalidParams(
                "username is required (the PIA p-number)".into(),
            ));
        }
        if ctrl(&self.username) || ctrl(&self.password) {
            return Err(Unsupported::InvalidParams(
                "username/password must not contain control characters".into(),
            ));
        }
        // a credential that EXACTLY equals a heredoc delimiter would
        // terminate its heredoc early and run as shell (Codex #514 P1:
        // termination requires the line to equal the delimiter alone)
        for field in [&self.username, &self.password] {
            if matches!(
                field.as_str(),
                "VPN_SETUP_EOF" | "PIA_CA_EOF" | "PIA_AUTH_EOF"
            ) {
                return Err(Unsupported::InvalidParams(
                    "username/password must not equal a heredoc delimiter".into(),
                ));
            }
        }
        if self.password.is_empty() {
            return Err(Unsupported::InvalidParams("password is required".into()));
        }
        if self.port.is_empty() || !self.port.chars().all(|c| c.is_ascii_digit()) {
            return Err(Unsupported::InvalidParams("port must be numeric".into()));
        }
        let ipv4 = |v: &str| {
            let o: Vec<&str> = v.split('.').collect();
            o.len() == 4
                && o.iter().all(|p| {
                    !p.is_empty()
                        && p.chars().all(|c| c.is_ascii_digit())
                        && p.parse::<u8>().is_ok()
                })
        };
        if !self.upstream_gateway.is_empty() && !ipv4(&self.upstream_gateway) {
            return Err(Unsupported::InvalidParams(
                "upstream_gateway must be an IPv4 address".into(),
            ));
        }
        if !self
            .upstream_iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        {
            return Err(Unsupported::InvalidParams(
                "upstream_iface contains unsafe characters".into(),
            ));
        }
        for r in &self.remotes {
            if !ipv4(r) {
                return Err(Unsupported::InvalidParams(format!(
                    "remotes entry {r:?} must be an IPv4 address"
                )));
            }
        }
        Ok(())
    }
}

/// NordVPN via NordLynx (WireGuard) — port of the tested 1.x
/// `vpn-nordvpn` preset (`scripts/use_cases/vpn_providers/nordvpn.py`,
/// hardware-verified 2026-10-08 on x1860/25.12.5). 1.x resolves
/// EVERYTHING at build time on the host (the NordLynx private key from
/// the token-gated credentials endpoint, the server from the
/// recommendations API) and the device receives a fully static config.
/// The host-side API resolution stays 1.x (M7 pipeline work); this
/// profile carries the RESOLVED statics — the same contract as a
/// dashboard-exported .conf, without secrets in git (goldens use
/// stubbed resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNordvpnProfile {
    /// Resolved NordLynx private key (base64). Rides a double-quoted
    /// assignment in the payload — validate() enforces the base64
    /// charset (the mwan3/#448 injection class).
    pub private_key: String,
    /// Server WireGuard public key (base64, same gate).
    pub server_public_key: String,
    /// Endpoint: IP or hostname (NordVPN per-server hostnames).
    pub endpoint_host: String,
    /// Resolved ROUTE TARGET for the endpoint /32 pin: when the
    /// endpoint is a hostname, 1.x resolves it to an IP at build time
    /// (the route option needs the IP); equal to endpoint_host when
    /// that is already an IPv4.
    pub route_target: String,
    /// Endpoint UDP port (string for 1.x parity; default 51820).
    pub endpoint_port: String,
    /// Tunnel address (1.x static 10.5.0.2/32).
    pub address: String,
    /// Tunnel MTU (1.x default 1420).
    pub mtu: String,
    /// Persistent keepalive (1.x default 25).
    pub keepalive: String,
    /// Upstream gateway IP; pins the endpoint /32 route (empty = the
    /// payload's bounded gateway discovery, 1.x parity).
    pub upstream_gateway: String,
    /// Upstream interface name (1.x default wwan).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops (default on; the
    /// 30s handshake verify loop auto-removes it on failure).
    pub kill_switch: bool,
    /// Accept SSH/LuCI from the VPN zone (default on).
    pub allow_management: bool,
}

impl Default for VpnNordvpnProfile {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            server_public_key: String::new(),
            endpoint_host: String::new(),
            route_target: String::new(),
            endpoint_port: "51820".into(),
            address: "10.5.0.2/32".into(),
            mtu: "1420".into(),
            keepalive: "25".into(),
            upstream_gateway: String::new(),
            upstream_iface: "wwan".into(),
            kill_switch: true,
            allow_management: true,
        }
    }
}

impl VpnNordvpnProfile {
    /// 1.x validates nothing on the resolved statics (they came from
    /// its own API calls). This plan interpolates them into a payload
    /// whose assignments are double-quoted, so the port gates: keys
    /// must be base64, the endpoint an IPv4 or a hostname, port/mtu/
    /// keepalive numeric, the address a CIDR, the iface on the 1.x
    /// charset (mwan3/#448 class).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let b64 = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        };
        if !b64(&self.private_key) {
            return Err(Unsupported::InvalidParams(
                "private_key must be base64".into(),
            ));
        }
        if !b64(&self.server_public_key) {
            return Err(Unsupported::InvalidParams(
                "server_public_key must be base64".into(),
            ));
        }
        let ipv4 = |v: &str| {
            let o: Vec<&str> = v.split('.').collect();
            o.len() == 4
                && o.iter().all(|p| {
                    !p.is_empty()
                        && p.chars().all(|c| c.is_ascii_digit())
                        && p.parse::<u8>().is_ok()
                })
        };
        let host_ok = |v: &str| {
            ipv4(v)
                || (!v.is_empty()
                    && v.len() <= 253
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
                    && !v.starts_with('-')
                    && !v.ends_with('-'))
        };
        if !host_ok(&self.endpoint_host) {
            return Err(Unsupported::InvalidParams(
                "endpoint_host must be an IPv4 or hostname".into(),
            ));
        }
        if self.route_target.is_empty() {
            return Err(Unsupported::InvalidParams(
                "route_target is required (the resolved endpoint IP)".into(),
            ));
        }
        if !ipv4(&self.route_target) {
            return Err(Unsupported::InvalidParams(
                "route_target must be an IPv4 address".into(),
            ));
        }
        for (field, value) in [
            ("endpoint_port", &self.endpoint_port),
            ("mtu", &self.mtu),
            ("keepalive", &self.keepalive),
        ] {
            if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must be numeric"
                )));
            }
        }
        let addr_ok = |v: &str| match v.rsplit_once('/') {
            Some((ip, prefix)) => {
                ipv4(ip)
                    && prefix.chars().all(|c| c.is_ascii_digit())
                    && prefix.parse::<u8>().is_ok_and(|p| p <= 32)
            }
            None => false,
        };
        if !addr_ok(&self.address) {
            return Err(Unsupported::InvalidParams(
                "address must be an IPv4 CIDR".into(),
            ));
        }
        if !self.upstream_gateway.is_empty() && !ipv4(&self.upstream_gateway) {
            return Err(Unsupported::InvalidParams(
                "upstream_gateway must be an IPv4 address".into(),
            ));
        }
        if !self
            .upstream_iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        {
            return Err(Unsupported::InvalidParams(
                "upstream_iface contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// One upstream WiFi the deploying host already knows the credentials
/// for — seeded onto the router so travelmate can join it onsite (the
/// "flash and it just works" flow: the deploying host's saved networks
/// become the router's uplink candidates). Secrets never appear in
/// plan debug output: `PlanOp` renders quote-escaped and verification
/// matches on non-secret anchors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiUplink {
    /// Network name to join.
    pub ssid: String,
    /// Passphrase (empty for open networks).
    pub psk: String,
    /// UCI encryption mode: `psk2`, `sae`, `psk2-sae` (mixed), `none`.
    pub encryption: String,
    /// Radio section the STA iface binds to, e.g. `radio0`.
    pub radio: String,
    /// wifi-iface section name, e.g. `trm_uplink1` (stable across
    /// re-applies for idempotent reconfigure).
    pub iface: String,
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
    /// Harden Dropbear SSH (key-only auth, timeouts, port).
    SshHardening(SshHardeningProfile),
    /// Travel-router auto-connect for captive-portal WiFi upstreams.
    Travelmate(TravelmateProfile),
    /// Network-wide ad blocking via AdGuard Home.
    Adguard(AdguardProfile),
    /// Automated 802.11s mesh networking.
    Mesh11sd(Mesh11sdProfile),
    /// Self-healing reboot when the management target goes unreachable.
    RescueWatchdog(RescueWatchdogProfile),
    /// Multi-WAN failover / load balancing.
    Mwan3(Mwan3Profile),
    /// nftables-native policy-based routing.
    Pbr(PbrProfile),
    /// Local DNS cache of nodns records via dnsmasq.
    Nodns(NodnsProfile),
    /// Auto-measured SQM (static or dynamic re-tune).
    AutoSqm(AutoSqmProfile),
    /// Isolated guest WiFi network.
    GuestWifi(GuestWifiProfile),
    /// Transparent proxy via Clash/Mihomo (flash-time config only —
    /// subscription import is post-flash via the LuCI web UI).
    OpenClash(OpenClashProfile),
    /// Trusted HTTPS certificates for LAN services (flash-time uhttpd
    /// wiring; cert download/SCP is a host-side post-flash step).
    Ssl(SslProfile),
    /// Private Internet Access via OpenVPN (validated static recipe;
    /// tun0, remote-random endpoint pool, kill switch).
    VpnPiaOpenvpn(VpnPiaOpenvpnProfile),
    /// NordVPN via NordLynx (WireGuard; resolved statics carried).
    VpnNordvpn(VpnNordvpnProfile),
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
            Profile::SshHardening(_) => "ssh-hardening",
            Profile::Travelmate(_) => "travelmate",
            Profile::Adguard(_) => "adguard",
            Profile::Mesh11sd(_) => "mesh11sd",
            Profile::RescueWatchdog(_) => "rescue-watchdog",
            Profile::Mwan3(_) => "mwan3",
            Profile::Pbr(_) => "pbr",
            Profile::Nodns(_) => "nodns",
            Profile::AutoSqm(_) => "auto-sqm",
            Profile::GuestWifi(_) => "guest-wifi",
            Profile::OpenClash(_) => "openclash",
            Profile::Ssl(_) => "ssl",
            Profile::VpnPiaOpenvpn(_) => "vpn-pia-openvpn",
            Profile::VpnNordvpn(_) => "vpn-nordvpn",
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
            Profile::SshHardening(_) => &[],
            Profile::Travelmate(_) => &["wifi"],
            Profile::Adguard(_) => &[],
            Profile::Mesh11sd(_) => &["wifi"],
            Profile::RescueWatchdog(_) => &[],
            Profile::Mwan3(_) => &[],
            Profile::Pbr(_) => &[],
            Profile::Nodns(_) => &[],
            Profile::AutoSqm(_) => &[],
            Profile::GuestWifi(_) => &["wifi"],
            Profile::OpenClash(_) => &[],
            Profile::Ssl(_) => &[],
            Profile::VpnPiaOpenvpn(_) => &[],
            Profile::VpnNordvpn(_) => &[],
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
    /// Start now (without restart semantics — 1.x `start`).
    Start,
}

impl fmt::Display for ServiceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceAction::Enable => write!(f, "enable"),
            ServiceAction::Restart => write!(f, "restart"),
            ServiceAction::Start => write!(f, "start"),
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
        Profile::SshHardening(sh) => plan_ssh_hardening(model, sh),
        Profile::Travelmate(tm) => plan_travelmate(model, tm),
        Profile::Adguard(ag) => plan_adguard(model, ag),
        Profile::Mesh11sd(mesh) => plan_mesh11sd(model, mesh),
        Profile::RescueWatchdog(wd) => plan_rescue_watchdog(model, wd),
        Profile::Mwan3(mw) => plan_mwan3(model, mw),
        Profile::Pbr(pbr) => plan_pbr(model, pbr),
        Profile::Nodns(nd) => plan_nodns(model, nd),
        Profile::AutoSqm(asq) => plan_auto_sqm(model, asq),
        Profile::GuestWifi(gw) => plan_guest_wifi(model, gw),
        Profile::OpenClash(oc) => plan_openclash(model, oc),
        Profile::Ssl(ssl) => plan_ssl(model, ssl),
        Profile::VpnPiaOpenvpn(pia) => plan_vpn_pia_openvpn(model, pia),
        Profile::VpnNordvpn(nv) => plan_vpn_nordvpn(model, nv),
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
            description: "resolver URL persisted exactly".into(),
            command: format!(
                "test \"$(uci -q get https-dns-proxy.main.resolver_url)\" = {url_q} && echo ok",
                url_q = shell_quote(&url)
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            description: "dnsmasq forwards to the local proxy".into(),
            command: format!(
                "uci -q get dhcp.@dnsmasq[0].server | grep -qx {entry} && echo ok",
                entry = shell_quote(&format!("127.0.0.1#{port}"))
            ),
            expect_contains: "ok".into(),
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
            name: "kmod-wireguard".into(),
        },
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
            name: "kmod-wireguard".into(),
        },
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

fn plan_ssh_hardening(model: &DeviceModel, sh: &SshHardeningProfile) -> Result<Plan, Unsupported> {
    let pw_auth = if sh.disable_password_auth {
        "off"
    } else {
        "on"
    };
    let gateway_ports = if sh.restrict_gateway_ports {
        "no"
    } else {
        "yes"
    };
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::SetUciOptions {
            config: "dropbear".into(),
            section: "@dropbear[0]".into(),
            options: vec![
                ("PasswordAuth".into(), literal(pw_auth.into())),
                ("RootPasswordAuth".into(), literal(pw_auth.into())),
                ("Port".into(), literal(sh.port.to_string())),
                ("IdleTimeout".into(), literal(sh.idle_timeout.to_string())),
                (
                    "MaxAuthTries".into(),
                    literal(sh.max_auth_tries.to_string()),
                ),
                ("GatewayPorts".into(), literal(gateway_ports.into())),
            ],
        },
        PlanOp::CommitUci {
            config: "dropbear".into(),
        },
        PlanOp::Service {
            name: "dropbear".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"SSH hardened: password_auth={pw_auth} idle={}s \
                 max_tries={} port={}\"",
                sh.idle_timeout, sh.max_auth_tries, sh.port
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "password auth mode persisted".into(),
            command: "uci -q get dropbear.@dropbear[0].PasswordAuth".into(),
            expect_contains: pw_auth.into(),
        },
        VerificationCheck {
            description: "listen port persisted".into(),
            command: "uci -q get dropbear.@dropbear[0].Port".into(),
            expect_contains: sh.port.to_string(),
        },
    ];
    Ok(Plan {
        profile_id: "ssh-hardening".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_travelmate(model: &DeviceModel, tm: &TravelmateProfile) -> Result<Plan, Unsupported> {
    let captive_flag = if tm.captive { "1" } else { "0" };
    let literal = |v: String| UciValue::Literal(v);
    let mut global_options = vec![
        ("trm_enabled".into(), literal("1".into())),
        ("trm_automatic".into(), literal("1".into())),
        ("trm_captive".into(), literal(captive_flag.into())),
        ("trm_timeout".into(), literal(tm.timeout.to_string())),
        ("trm_retry".into(), literal(tm.retry.to_string())),
        ("trm_radio".into(), literal(tm.radio.clone())),
    ];
    if !tm.uplinks.is_empty() {
        global_options.push(("trm_iface".into(), literal("trm_wwan".into())));
        global_options.push(("trm_uplink".into(), literal("trm_wwan".into())));
    }
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "travelmate".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-travelmate".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-certificates".into(),
        },
        PlanOp::SetUciOptions {
            config: "travelmate".into(),
            section: "global".into(),
            options: global_options,
        },
    ];
    if !tm.uplinks.is_empty() {
        // Mirror of travelmate's own `setup` command shape (2.4.x): the
        // trm_iface gate in travelmate-functions.sh exits "not
        // configured" without it; the uplink pair is trm_wwan (dhcp,
        // metric 100) + trm_wwan6 (dhcpv6 via @trm_wwan), both joined
        // to the wan zone by NAME via the 1.x helper.
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "trm_wwan".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("dhcp".into())),
                ("metric".into(), literal("100".into())),
            ],
        });
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "trm_wwan6".into(),
            section_type: "interface".into(),
            options: vec![
                ("device".into(), literal("@trm_wwan".into())),
                ("proto".into(), literal("dhcpv6".into())),
            ],
        });
        ops.push(PlanOp::Shell {
            command: uci_add_to_wan_zone_sh("trm_wwan"),
        });
        ops.push(PlanOp::Shell {
            command: uci_add_to_wan_zone_sh("trm_wwan6"),
        });
        for uplink in &tm.uplinks {
            let mut options = vec![
                ("device".into(), literal(uplink.radio.clone())),
                ("mode".into(), literal("sta".into())),
                ("network".into(), literal("trm_wwan".into())),
                ("ssid".into(), literal(uplink.ssid.clone())),
                ("encryption".into(), literal(uplink.encryption.clone())),
            ];
            if uplink.encryption != "none" {
                options.push(("key".into(), literal(uplink.psk.clone())));
            }
            ops.push(PlanOp::SetUciSection {
                config: "wireless".into(),
                section: uplink.iface.clone(),
                section_type: "wifi-iface".into(),
                options,
            });
            // travelmate 2.4.x recognition: each sta wifi-iface needs a
            // paired `uplink` section in /etc/config/travelmate (matched
            // by device+ssid in f_getcfg) carrying enabled=1 — without
            // it f_setif force-disables the iface and the sta_list stays
            // empty (found live on x1860-1, 2026-10-22).
            ops.push(PlanOp::SetUciSection {
                config: "travelmate".into(),
                section: uplink.iface.clone(),
                section_type: "uplink".into(),
                options: vec![
                    ("device".into(), literal(uplink.radio.clone())),
                    ("ssid".into(), literal(uplink.ssid.clone())),
                    ("enabled".into(), literal("1".into())),
                ],
            });
        }
        ops.push(PlanOp::CommitUci {
            config: "network".into(),
        });
        ops.push(PlanOp::CommitUci {
            config: "wireless".into(),
        });
        ops.push(PlanOp::Shell {
            command: "wifi reload; ubus call network.interface.trm_wwan up 2>/dev/null; true"
                .into(),
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "travelmate".into(),
    });
    ops.push(PlanOp::Service {
        name: "travelmate".into(),
        action: ServiceAction::Enable,
    });
    ops.push(PlanOp::Service {
        name: "travelmate".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "echo \"Travelmate configured: auto-connect on {}\"",
            tm.radio
        ),
    });
    let verification = vec![
        VerificationCheck {
            description: "travelmate enabled".into(),
            command: "uci -q get travelmate.global.trm_enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "scan radio persisted".into(),
            command: "uci -q get travelmate.global.trm_radio".into(),
            expect_contains: tm.radio.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/travelmate enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "travelmate".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_adguard(model: &DeviceModel, ag: &AdguardProfile) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "adguardhome".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-adguardhome".into(),
        },
        PlanOp::SetUciSection {
            config: "adguardhome".into(),
            section: "adguardhome".into(),
            section_type: "adguardhome".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                (
                    "http_address".into(),
                    literal(format!("{}:{}", ag.listen_ip, ag.web_port)),
                ),
                ("dns_port".into(), literal(ag.dns_port.to_string())),
            ],
        },
        PlanOp::CommitUci {
            config: "adguardhome".into(),
        },
        PlanOp::Service {
            name: "adguardhome".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "adguardhome".into(),
            action: ServiceAction::Start,
        },
        PlanOp::SetUciOptions {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            options: vec![("noresolv".into(), literal("1".into()))],
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: format!("127.0.0.1#{}", ag.dns_port),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"AdGuard Home configured: DNS on port {}, web UI at {}:{}\"",
                ag.dns_port, ag.listen_ip, ag.web_port
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "adguardhome enabled in uci".into(),
            command: "uci -q get adguardhome.adguardhome.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "dnsmasq forwards to adguard".into(),
            command: "uci -q get dhcp.@dnsmasq[0].server".into(),
            expect_contains: format!("127.0.0.1#{}", ag.dns_port),
        },
    ];
    Ok(Plan {
        profile_id: "adguard".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_mesh11sd(model: &DeviceModel, mesh: &Mesh11sdProfile) -> Result<Plan, Unsupported> {
    mesh.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut setup_options = vec![
        ("auto_mesh_id".into(), literal(mesh.mesh_id.clone())),
        ("mesh_gate_base_ssid".into(), literal(mesh.ssid.clone())),
        (
            "mesh_gate_encryption".into(),
            literal(mesh.encryption.clone()),
        ),
    ];
    if !mesh.key.is_empty() {
        setup_options.push(("mesh_gate_key".into(), literal(mesh.key.clone())));
    }
    setup_options.push(("auto_config".into(), literal(mesh.auto_config.clone())));
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "mesh11sd".into(),
        },
        PlanOp::EnsurePackage {
            name: "ip-full".into(),
        },
        PlanOp::EnsurePackage {
            name: "kmod-nft-bridge".into(),
        },
        PlanOp::EnsurePackage {
            name: "vxlan".into(),
        },
        PlanOp::Shell {
            command: "opkg remove wpad-basic-mbedtls wpad-basic-wolfssl wpad-basic-openssl \
                      wpad-basic 2>/dev/null || true"
                .into(),
        },
        PlanOp::Shell {
            command: "opkg install wpad-mbedtls 2>/dev/null || true".into(),
        },
        PlanOp::Shell {
            command: "service wpad restart 2>/dev/null || true".into(),
        },
        PlanOp::SetUciOptions {
            config: "mesh11sd".into(),
            section: "setup".into(),
            options: setup_options,
        },
        PlanOp::CommitUci {
            config: "mesh11sd".into(),
        },
        PlanOp::Shell {
            command: "service mesh11sd restart 2>/dev/null || true".into(),
        },
        PlanOp::Shell {
            command: format!(
                "echo \"Mesh11sd configured: mesh_id={} ssid={}\"",
                mesh.mesh_id, mesh.ssid
            ),
        },
    ];
    let verification = vec![VerificationCheck {
        description: "mesh id persisted".into(),
        command: "uci -q get mesh11sd.setup.auto_mesh_id".into(),
        expect_contains: mesh.mesh_id.clone(),
    }];
    Ok(Plan {
        profile_id: "mesh11sd".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

/// The 1.x watchdog payload, verbatim (`WATCHDOG_INIT` in
/// `scripts/use_cases/rescue_watchdog.py`): procd init heredoc +
/// watchdog loop heredoc, `__TARGET__` substituted at plan time.
const RESCUE_WATCHDOG_INIT: &str = r#"cat > /etc/init.d/rescue-watchdog << 'WD_EOF'
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh /usr/bin/rescue-watchdog-loop
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
WD_EOF
chmod +x /etc/init.d/rescue-watchdog

/usr/bin/rescue-watchdog-loop << 'WDL_EOF'
#!/bin/sh
TARGET="${WATCHDOG_TARGET:-__TARGET__}"
GRACE=600
FAILS=0
while :; do
    UPTIME=$(cut -d. -f1 /proc/uptime)
    if [ "$UPTIME" -lt "$GRACE" ]; then
        FAILS=0
    elif ping -c1 -W3 "$TARGET" >/dev/null 2>&1; then
        FAILS=0
    else
        FAILS=$((FAILS+1))
        logger -t rescue-watchdog "target $TARGET unreachable ($FAILS/3)"
        if [ "$FAILS" -ge 3 ]; then
            logger -t rescue-watchdog "networking wedged - rebooting"
            sync
            reboot
        fi
    fi
    sleep 60
done
WDL_EOF
chmod +x /usr/bin/rescue-watchdog-loop

/etc/init.d/rescue-watchdog enable
/etc/init.d/rescue-watchdog restart
"#;

/// Local DNS cache of nodns records — port of the tested 1.x `nodns`
/// preset (`scripts/use_cases/nodns.py`, verified on 24.10.2 QEMU). A
/// procd service polls the nodns bot's BIND zone export every
/// `poll_interval` and rewrites `/etc/dnsmasq.d/nodns.hosts`
/// (addn-hosts), SIGHUPing dnsmasq. Zero packages: curl + sh only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodnsProfile {
    /// DNS zone to cache (1.x default `nodns.shop`).
    pub zone: String,
    /// nodns bot API base URL (1.x default `https://nodns.shop`).
    pub api_url: String,
    /// Polling interval in seconds (1.x `int_range` 60–86400, default 300).
    pub poll_interval: u32,
}

impl Default for NodnsProfile {
    fn default() -> Self {
        Self {
            zone: "nodns.shop".into(),
            api_url: "https://nodns.shop".into(),
            poll_interval: 300,
        }
    }
}

impl NodnsProfile {
    /// 1.x validators: `int_range(60, 86400)` for the interval, an
    /// http(s):// prefix gate for the URL, and non-empty/no-whitespace
    /// for the zone. All three string values are additionally checked
    /// for shell metacharacters: they land inside the runtime script's
    /// double-quoted assignments, where `$(...)`/backticks would
    /// command-substitute when the poll script RUNS (1.x shares the
    /// hole; the port refuses hostile input instead).
    pub fn validate(&self) -> Result<(), Unsupported> {
        const SHELL_META: &[char] = &['$', '`', '(', ')', ';', '&', '|', '<', '>', '"', '\''];
        if !(60..=86_400).contains(&self.poll_interval) {
            return Err(Unsupported::InvalidParams(
                "poll_interval must be 60-86400 seconds".into(),
            ));
        }
        for (field, value) in [("api_url", &self.api_url), ("zone", &self.zone)] {
            if value.contains(SHELL_META) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} contains shell metacharacters"
                )));
            }
        }
        if !(self.api_url.starts_with("https://") || self.api_url.starts_with("http://")) {
            return Err(Unsupported::InvalidParams(
                "api_url must start with https:// or http://".into(),
            ));
        }
        if self.zone.is_empty() || self.zone.chars().any(|c| c.is_whitespace()) {
            return Err(Unsupported::InvalidParams(
                "zone must not be empty or contain spaces".into(),
            ));
        }
        Ok(())
    }
}

const NODNS_INITD_SCRIPT: &str = r####"#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/nodns-poll.sh
	procd_set_param respawn
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
"####;

const NODNS_POLL_SCRIPT_TEMPLATE: &str = r####"#!/bin/sh
# nodns DNS bridge -- polls zone export API, updates dnsmasq addn-hosts cache.
# Auto-generated by conwrt use_cases/nodns.
ZONE="__ZONE__"
API_URL="__URL__"
POLL_INTERVAL=__POLL_INTERVAL__
HOSTS_FILE="/etc/dnsmasq.d/nodns.hosts"
TMP_FILE="/tmp/nodns-zone.txt"

mkdir -p /etc/dnsmasq.d

while true; do
	# Fetch BIND zone file from the nodns bot API.
	if curl -s --connect-timeout 10 --max-time 30 \
		"${API_URL}/api/zone/${ZONE}/export" \
		-o "$TMP_FILE" 2>/dev/null; then
		# Parse: extract A/AAAA records -> "ip<TAB>fqdn" lines for addn-hosts.
		awk -v z="$ZONE" '
		BEGIN { OFS = "\t" }
		{
			rtype = toupper($3)
			if (rtype != "A" && rtype != "AAAA") next
			name = $1
			ip = $NF
			if (name == "@") name = z
			else if (name ~ /\.$/) sub(/\.$/, "", name)
			else name = name "." z
			print ip, name
		}' "$TMP_FILE" > "$HOSTS_FILE.new"
		# Atomic swap only when we got valid data.
		if [ -s "$HOSTS_FILE.new" ]; then
			mv "$HOSTS_FILE.new" "$HOSTS_FILE"
			killall -HUP dnsmasq 2>/dev/null
		else
			rm -f "$HOSTS_FILE.new"
		fi
	fi
	sleep "$POLL_INTERVAL"
done
"####;

/// Auto-measured SQM — port of the tested 1.x `auto-sqm` preset
/// (`scripts/use_cases/auto_sqm.py`, verified on 24.10.2 QEMU). A
/// runtime script (rendered byte-verbatim below) reads its whole
/// configuration from `auto_sqm.config` uci at RUN time — static mode
/// applies fixed speeds immediately, dynamic mode re-measures on a
/// cron schedule; a hotplug hook re-tunes on WAN ifup. The plan only
/// stages the config, the script, the hook, and (dynamic) the cron
/// entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoSqmProfile {
    /// `static` (fixed speeds) or `dynamic` (auto-measure + cron re-tune).
    pub mode: String,
    /// WAN UCI interface name (1.x `interface_name` charset).
    pub interface: String,
    /// Physical device for byte counters (same charset).
    pub device: String,
    /// Apply SQM at this % of measured speed (1.x default 90).
    pub target_percent: u32,
    /// Queue discipline: cake or fq_codel.
    pub qdisc: String,
    /// QoS script (1.x default `piece_of_cake.qos`).
    pub script: String,
    /// Measurement mode: wget or iperf3.
    pub measurement_mode: String,
    /// Static download Kbit/s (0 = measure on first trigger).
    pub download_kbps: u32,
    /// Static upload Kbit/s (0 = use the fallback).
    pub upload_kbps: u32,
    /// iperf3 server hostname (required for iperf3 mode).
    pub iperf3_host: String,
    /// iperf3 server port.
    pub iperf3_port: u16,
    /// wget test file URL for speed measurement.
    pub test_url: String,
    /// Fallback upload speed when unmeasurable (Kbit/s).
    pub upload_fallback_kbps: u32,
    /// Skip reconfiguration when the change is below this %.
    pub hysteresis_percent: u32,
    /// Re-tune interval in hours (dynamic mode).
    pub dynamic_interval_hours: u32,
}

impl Default for AutoSqmProfile {
    fn default() -> Self {
        Self {
            mode: "static".into(),
            interface: "wan".into(),
            device: "eth0".into(),
            target_percent: 90,
            qdisc: "cake".into(),
            script: "piece_of_cake.qos".into(),
            measurement_mode: "wget".into(),
            download_kbps: 0,
            upload_kbps: 0,
            iperf3_host: String::new(),
            iperf3_port: 5201,
            test_url: "http://speedtest.tele2.net/10MB.zip".into(),
            upload_fallback_kbps: 5000,
            hysteresis_percent: 10,
            dynamic_interval_hours: 4,
        }
    }
}

impl AutoSqmProfile {
    /// 1.x validates exactly two fields (`interface_name` on interface
    /// and device); everything else rides uci at run time.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.interface) {
            return Err(Unsupported::InvalidParams(
                "WAN interface contains unsafe characters".into(),
            ));
        }
        if !iface_ok(&self.device) {
            return Err(Unsupported::InvalidParams(
                "SQM device contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

const AUTO_SQM_SCRIPT: &str = r####"#!/bin/sh
# auto-sqm — measure WAN link speed and configure SQM

MODE=$(uci -q get auto_sqm.config.mode || echo "static")
INTERFACE=$(uci -q get auto_sqm.config.interface || echo "wan")
DEVICE=$(uci -q get auto_sqm.config.device || echo "eth0")
TARGET_PCT=$(uci -q get auto_sqm.config.target_percent || echo "90")
QDISC=$(uci -q get auto_sqm.config.qdisc || echo "cake")
QOS_SCRIPT=$(uci -q get auto_sqm.config.script || echo "piece_of_cake.qos")
MEAS_MODE=$(uci -q get auto_sqm.config.measurement_mode || echo "wget")
IPERF3_HOST=$(uci -q get auto_sqm.config.iperf3_host || echo "")
IPERF3_PORT=$(uci -q get auto_sqm.config.iperf3_port || echo "5201")
TEST_URL=$(uci -q get auto_sqm.config.test_url || echo "")
UPLOAD_FALLBACK=$(uci -q get auto_sqm.config.upload_fallback_kbps || echo "5000")
HYSTERESIS=$(uci -q get auto_sqm.config.hysteresis_percent || echo "10")

DL_SPEED=0
UL_SPEED=0

measure_wget() {
    [ -z "$DEVICE" ] && return 1
    [ -z "$TEST_URL" ] && return 1
    bytes_before=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    t1=$(date +%s)
    wget -O /dev/null -T 30 "$TEST_URL" 2>/dev/null || return 1
    t2=$(date +%s)
    bytes_after=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    elapsed=$((t2 - t1))
    [ "$elapsed" -eq 0 ] && elapsed=1
    speed_bps=$(( (bytes_after - bytes_before) * 8 / elapsed ))
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

measure_iperf3() {
    [ -z "$IPERF3_HOST" ] && return 1
    command -v iperf3 >/dev/null 2>&1 || return 1
    json_out=$(iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -t 5 -J 2>/dev/null) || return 1
    speed_bps=$(echo "$json_out" | jsonfilter -e "@.end.sum_received.bits_per_second" 2>/dev/null) || return 1
    speed_bps=$(echo "$speed_bps" | cut -d. -f1)
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

apply_sqm() {
    dl=$1
    ul=$2
    [ "$dl" -eq 0 ] && return 1

    cur_dl=$(uci -q get sqm."$INTERFACE".download || echo "0")
    cur_ul=$(uci -q get sqm."$INTERFACE".upload || echo "0")

    if [ "$cur_dl" -gt 0 ] && [ "$cur_ul" -gt 0 ]; then
        lo=$((100 - HYSTERESIS))
        hi=$((100 + HYSTERESIS))
        pct_dl=$((cur_dl * 100 / dl))
        pct_ul=$((cur_ul * 100 / ul))
        if [ "$pct_dl" -ge "$lo" ] && [ "$pct_dl" -le "$hi" ] && [ "$pct_ul" -ge "$lo" ] && [ "$pct_ul" -le "$hi" ]; then
            echo "auto-sqm: change within hysteresis, skipping"
            return 0
        fi
    fi

    # clean baseline first: /tmp/.uci staging debris from an aborted
    # earlier run must not merge into this commit (#470, AGENTS uci rule)
    uci revert sqm 2>/dev/null || true
    touch /etc/config/sqm

    uci set sqm.$INTERFACE=queue
    # SQM must bind the actual device, not the UCI network name (#470 —
    # the wan lesson: names break on WiFi-STA/alias setups where
    # device != name). Resolve via the network section, then the
    # configured DEVICE, then fall back to the name.
    _sqm_dev=$(uci -q get network."$INTERFACE".device 2>/dev/null)
    [ -z "$_sqm_dev" ] && _sqm_dev="$DEVICE"
    [ -z "$_sqm_dev" ] && _sqm_dev="$INTERFACE"
    uci set sqm.$INTERFACE.interface="$_sqm_dev"
    uci set sqm.$INTERFACE.enabled='1'
    uci set sqm.$INTERFACE.script="$QOS_SCRIPT"
    uci set sqm.$INTERFACE.qdisc="$QDISC"
    uci set sqm.$INTERFACE.linklayer='none'
    uci set sqm.$INTERFACE.overhead='0'
    uci set sqm.$INTERFACE.linklayer_adaptation_mechanism='default'
    uci set sqm.$INTERFACE.debug_logging='0'
    uci set sqm.$INTERFACE.verbosity='5'
    uci set sqm.$INTERFACE.download="$dl"
    uci set sqm.$INTERFACE.upload="$ul"
    uci commit sqm

    /etc/init.d/sqm enable
    /etc/init.d/sqm restart 2>/dev/null || true

    echo "auto-sqm: SQM applied ${dl}/${ul} kbit/s (${QDISC})"
}

STATIC_DL=$(uci -q get auto_sqm.config.download_kbps || echo "0")
STATIC_UL=$(uci -q get auto_sqm.config.upload_kbps || echo "0")

if [ "$MODE" = "static" ] && [ "$STATIC_DL" -gt 0 ]; then
    DL_SPEED=$((STATIC_DL * TARGET_PCT / 100))
    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
else
    if [ "$MEAS_MODE" = "iperf3" ] && [ -n "$IPERF3_HOST" ]; then
        measure_iperf3 || measure_wget
    else
        measure_wget || measure_iperf3
    fi

    if [ "$DL_SPEED" -eq 0 ]; then
        echo "auto-sqm: measurement failed, will retry on next trigger" >&2
        exit 1
    fi

    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
fi

apply_sqm "$DL_SPEED" "$UL_SPEED"
"####;

fn plan_rescue_watchdog(
    model: &DeviceModel,
    wd: &RescueWatchdogProfile,
) -> Result<Plan, Unsupported> {
    let ops = vec![PlanOp::Shell {
        command: RESCUE_WATCHDOG_INIT.replace("__TARGET__", &wd.target),
    }];
    let verification = vec![VerificationCheck {
        description: "watchdog service enabled".into(),
        command: "/etc/init.d/rescue-watchdog enabled && echo yes".into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "rescue-watchdog".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_mwan3(model: &DeviceModel, mw: &Mwan3Profile) -> Result<Plan, Unsupported> {
    mw.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let (primary_metric, primary_weight, secondary_metric, secondary_weight) =
        if mw.policy == "balanced" {
            ("1", "2", "1", "1")
        } else {
            ("1", "1", "2", "1")
        };
    let pm = format!("{}_m{primary_metric}_w{primary_weight}", mw.primary);
    let sm = format!("{}_m{secondary_metric}_w{secondary_weight}", mw.secondary);
    let pol_name = format!("{}_policy", mw.primary);
    let probe_options = vec![
        ("family".into(), literal("ipv4".into())),
        ("reliability".into(), literal("1".into())),
        ("count".into(), literal("1".into())),
        ("timeout".into(), literal("2".into())),
        ("interval".into(), literal("5".into())),
        ("down".into(), literal("3".into())),
        ("up".into(), literal("8".into())),
    ];
    let mut ops: Vec<PlanOp> = [
        "mwan3",
        "iptables-nft",
        "ip6tables-nft",
        "iptables-mod-conntrack-extra",
    ]
    .iter()
    .map(|name| PlanOp::EnsurePackage {
        name: (*name).into(),
    })
    .collect();
    // mwan3 convention: the tracked interface section is named after the
    // UCI network it tracks. 1.x hardcoded the section as `wan` while
    // pointing the member at `primary` — broken for any primary ≠ "wan"
    // (Codex #448 P1; default output renders identically, so golden
    // parity is unaffected).
    ops.push(PlanOp::ResetUciConfig {
        config: "mwan3".into(),
    });
    for section in [&mw.primary, &mw.secondary] {
        ops.push(PlanOp::SetUciSection {
            config: "mwan3".into(),
            section: section.clone(),
            section_type: "interface".into(),
            options: vec![("enabled".into(), literal("1".into()))],
        });
        for ip in &mw.track_ips {
            // 1.x renders bare `list track_ip '<ip>'` lines here — broken
            // shell (silently ignored without set -e, fatal with it); the
            // port emits the intended uci add_list against THIS section
            ops.push(PlanOp::UciAddList {
                config: "mwan3".into(),
                section: section.clone(),
                option: "track_ip".into(),
                value: ip.clone(),
            });
        }
        ops.push(PlanOp::SetUciOptions {
            config: "mwan3".into(),
            section: section.clone(),
            options: probe_options.clone(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: pm.clone(),
        section_type: "member".into(),
        options: vec![
            ("interface".into(), literal(mw.primary.clone())),
            ("metric".into(), literal(primary_metric.into())),
            ("weight".into(), literal(primary_weight.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: sm.clone(),
        section_type: "member".into(),
        options: vec![
            ("interface".into(), literal(mw.secondary.clone())),
            ("metric".into(), literal(secondary_metric.into())),
            ("weight".into(), literal(secondary_weight.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: pol_name.clone(),
        section_type: "policy".into(),
        options: vec![],
    });
    ops.push(PlanOp::UciAddList {
        config: "mwan3".into(),
        section: pol_name.clone(),
        option: "use_member".into(),
        value: pm.clone(),
    });
    ops.push(PlanOp::UciAddList {
        config: "mwan3".into(),
        section: pol_name.clone(),
        option: "use_member".into(),
        value: sm.clone(),
    });
    ops.push(PlanOp::SetUciOptions {
        config: "mwan3".into(),
        section: pol_name.clone(),
        options: vec![("last_resort".into(), literal("default".into()))],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: "default_rule_v4".into(),
        section_type: "rule".into(),
        options: vec![
            ("dest_ip".into(), literal("0.0.0.0/0".into())),
            ("use_policy".into(), literal(pol_name.clone())),
            ("family".into(), literal("ipv4".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: "https_rule".into(),
        section_type: "rule".into(),
        options: vec![
            ("dest_port".into(), literal("443".into())),
            ("proto".into(), literal("tcp".into())),
            ("sticky".into(), literal("1".into())),
            ("use_policy".into(), literal(pol_name.clone())),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "mwan3".into(),
    });
    ops.push(PlanOp::Service {
        name: "mwan3".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "echo \"mwan3 configured: {} (primary) + {} ({})\"",
            mw.primary, mw.secondary, mw.policy
        ),
    });
    let verification = vec![
        VerificationCheck {
            description: "primary interface section exists".into(),
            command: "uci -q get mwan3.wan.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "policy wired to both members".into(),
            command: format!("uci -q get mwan3.{pol_name}.use_member"),
            expect_contains: pm,
        },
    ];
    Ok(Plan {
        profile_id: "mwan3".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_pbr(model: &DeviceModel, pbr: &PbrProfile) -> Result<Plan, Unsupported> {
    pbr.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let strict = if pbr.strict_enforcement { "1" } else { "0" };
    let ops = vec![
        PlanOp::EnsurePackage { name: "pbr".into() },
        PlanOp::EnsurePackage {
            name: "luci-app-pbr".into(),
        },
        PlanOp::Shell {
            command: "uci set pbr.config=pbr".into(),
        },
        PlanOp::SetUciOptions {
            config: "pbr".into(),
            section: "config".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                ("verbosity".into(), literal("2".into())),
                ("strict_enforcement".into(), literal(strict.into())),
                ("resolver_set".into(), literal("none".into())),
                ("nft_file_helper".into(), literal("1".into())),
            ],
        },
        // 1.x renders these two UNQUOTED (bare interface names); the
        // validate() charset gate is what makes the verbatim render safe.
        PlanOp::Shell {
            command: format!(
                "uci set pbr.config.netifd_interface_default={}",
                pbr.wan_interface
            ),
        },
        PlanOp::Shell {
            command: format!(
                "uci add_list pbr.config.netifd_interface_local={}",
                pbr.lan_interface
            ),
        },
        PlanOp::CommitUci {
            config: "pbr".into(),
        },
        PlanOp::Service {
            name: "pbr".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "pbr".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: "echo \"pbr configured. Verify with: nft list table inet pbr 2>/dev/null\""
                .into(),
        },
        PlanOp::Shell {
            command: "echo \"Check status: /etc/init.d/pbr status\"".into(),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "pbr enabled in uci".into(),
            command: "uci -q get pbr.config.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "default WAN interface persisted".into(),
            command: "uci -q get pbr.config.netifd_interface_default".into(),
            expect_contains: pbr.wan_interface.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/pbr enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "pbr".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_openclash(model: &DeviceModel, oc: &OpenClashProfile) -> Result<Plan, Unsupported> {
    oc.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    // Package order and swap safety are load-bearing at apply time
    // (Codex #486 rounds 1+4+6): dnsmasq and dnsmasq-full conflict
    // (both provide dnsmasq), luci-app-openclash DEPENDS on
    // dnsmasq-full, and the removal must never run before the
    // replacement is provably installable — a dead feed after a bare
    // removal would leave the router with NO dnsmasq (DNS+DHCP outage
    // class). The swap therefore: runs only when dnsmasq is installed
    // AND dnsmasq-full is not; downloads the dnsmasq-full ipk to /tmp
    // FIRST (proving feed + package availability); and only then
    // removes and installs from the local file (offline-safe). 1.x
    // carries the swap as an image-build `packages_remove` directive
    // where none of this applies. No-op on apk systems (opkg absent;
    // apk replaces the provider without a conflict) and where
    // dnsmasq-full is already installed.
    let mut ops: Vec<PlanOp> = vec![
        PlanOp::Shell {
            command: concat!(
                "if [ -n \"$(opkg list-installed dnsmasq 2>/dev/null)\" ] ",
                "&& [ -z \"$(opkg list-installed dnsmasq-full 2>/dev/null)\" ]; then ",
                "(cd /tmp && opkg update && opkg download dnsmasq-full) ",
                "&& opkg remove dnsmasq && opkg install /tmp/dnsmasq-full_*.ipk; fi",
            )
            .into(),
        },
        PlanOp::EnsurePackage {
            name: "dnsmasq-full".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-openclash".into(),
        },
        PlanOp::EnsurePackage {
            name: "coreutils-nohup".into(),
        },
        PlanOp::EnsurePackage {
            name: "bash".into(),
        },
        PlanOp::EnsurePackage {
            name: "iptables".into(),
        },
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-certificates".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
        PlanOp::EnsurePackage {
            name: "logd".into(),
        },
    ];
    ops.extend([
        PlanOp::Shell {
            command: "mkdir -p /etc/openclash/config".into(),
        },
        // AGENTS.md staging-debris rule: an aborted earlier session may
        // have left uncommitted /tmp/.uci changes for openclash — the
        // later `uci commit openclash` would make them permanent.
        // Start every apply from the persisted baseline.
        PlanOp::RevertUci {
            config: "openclash".into(),
        },
        PlanOp::SetUciOptions {
            config: "openclash".into(),
            section: "config".into(),
            options: vec![
                ("enable".into(), literal("1".into())),
                (
                    "config_path".into(),
                    literal("/etc/openclash/config/config.yaml".into()),
                ),
                ("proxy_type".into(), literal(oc.proxy_type.clone())),
                ("core_type".into(), literal(oc.core_type.clone())),
                ("dashboard_type".into(), literal("Official".into())),
                ("dns_mode".into(), literal(oc.dns_mode.clone())),
                ("operation_mode".into(), literal(oc.dns_mode.clone())),
            ],
        },
        PlanOp::CommitUci {
            config: "openclash".into(),
        },
        PlanOp::Service {
            name: "openclash".into(),
            action: ServiceAction::Enable,
        },
        // core_type/proxy_type interpolate into a DOUBLE-quoted echo;
        // validate()'s token gate is what makes the verbatim render safe
        PlanOp::Shell {
            command: format!(
                "echo \"OpenClash configured: {} core, {} proxy\"",
                oc.core_type, oc.proxy_type
            ),
        },
        // post-flash boundary, byte-identical to 1.x: the subscription
        // config is imported via the LuCI web UI AFTER flash — this
        // plan stops here
        PlanOp::Shell {
            command: "echo \"Post-flash: import your subscription config via the LuCI web UI\""
                .into(),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "openclash enabled in uci".into(),
            command: "uci -q get openclash.config.enable".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "clash core persisted".into(),
            command: "uci -q get openclash.config.core_type".into(),
            expect_contains: oc.core_type.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/openclash enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "openclash".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

const PIA_OPENVPN_CA: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD\n",
    "VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV\n",
    "BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu\n",
    "dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx\n",
    "IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB\n",
    "FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw\n",
    "MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex\n",
    "EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg\n",
    "QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE\n",
    "AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50\n",
    "ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy\n",
    "bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk\n",
    "hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN\n",
    "De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K\n",
    "V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ\n",
    "25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND\n",
    "fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl\n",
    "p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p\n",
    "Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj\n",
    "tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi\n",
    "jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz\n",
    "meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz\n",
    "1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV\n",
    "HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt\n",
    "yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI\n",
    "EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl\n",
    "cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw\n",
    "HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0\n",
    "ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl\n",
    "aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq\n",
    "hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt\n",
    "pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv\n",
    "Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G\n",
    "tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu\n",
    "LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs\n",
    "6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3\n",
    "5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX\n",
    "JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ\n",
    "iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l\n",
    "8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW\n",
    "+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=\n",
    "-----END CERTIFICATE-----\n",
);

fn plan_vpn_pia_openvpn(
    model: &DeviceModel,
    pia: &VpnPiaOpenvpnProfile,
) -> Result<Plan, Unsupported> {
    pia.validate()?;
    let remote_lines = pia
        .remotes
        .iter()
        .map(|host| {
            format!(
                "uci add_list openvpn.pia.remote='{host} {port}'",
                port = pia.port
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let route_block = if pia.upstream_gateway.is_empty() {
        String::new()
    } else {
        format!(
            "# pin the endpoint pool's route to the upstream (no v4 route via tun)\nfor _pia_ep in {}; do\n    ip route replace $_pia_ep/32 via {} dev {} 2>/dev/null || true\ndone\n",
            pia.remotes.join(" "),
            pia.upstream_gateway,
            pia.upstream_iface
        )
    };
    // the whole setup rides ONE heredoc payload (1.x transport_sh):
    // single-quoted delimiter keeps variables literal at write time and
    // the body runs verbatim via sh. username/password land as literal
    // auth lines — validate()'s control-character gate makes that safe.
    let body = format!(
        concat!(
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n\n",
            "# Tear down any previous OpenVPN instance\n",
            "uci -q delete openvpn.pia\n",
            "\n",
            "mkdir -p /etc/openvpn\n",
            "cat > /etc/openvpn/pia-ca.rsa.4096.crt << 'PIA_CA_EOF'\n",
            "{CA}\n",
            "PIA_CA_EOF\n",
            "cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'\n",
            "{USERNAME}\n",
            "{PASSWORD}\n",
            "PIA_AUTH_EOF\n",
            "chmod 600 /etc/openvpn/pia.auth\n",
            "\n",
            "uci set openvpn.pia=openvpn\n",
            "uci set openvpn.pia.enabled='1'\n",
            "uci set openvpn.pia.client='1'\n",
            "uci set openvpn.pia.dev='tun'\n",
            "uci set openvpn.pia.proto='udp'\n",
            "{REMOTE_LINES}\n",
            "uci set openvpn.pia.remote_random='1'\n",
            "uci set openvpn.pia.resolv_retry='infinite'\n",
            "uci set openvpn.pia.nobind='1'\n",
            "uci set openvpn.pia.persist_key='1'\n",
            "# NO persist_tun (validated lesson): a dead tunnel must tear its routes\n",
            "# down, not blackhole the LAN behind stale routes.\n",
            "uci set openvpn.pia.ca='/etc/openvpn/pia-ca.rsa.4096.crt'\n",
            "uci set openvpn.pia.auth_user_pass='/etc/openvpn/pia.auth'\n",
            "uci set openvpn.pia.auth_nocache='1'\n",
            "uci set openvpn.pia.remote_cert_tls='server'\n",
            "uci set openvpn.pia.data_ciphers='AES-256-GCM:AES-128-GCM:AES-256-CBC'\n",
            "uci set openvpn.pia.data_ciphers_fallback='AES-256-CBC'\n",
            "uci set openvpn.pia.auth='sha256'\n",
            "uci set openvpn.pia.reneg_sec='0'\n",
            "uci set openvpn.pia.disable_occ='1'\n",
            "uci set openvpn.pia.mssfix='1420'\n",
            "uci set openvpn.pia.verb='3'\n",
            "uci set openvpn.pia.pull='1'\n",
            "# PIA has no IPv6: it pushes route-ipv6/ifconfig-ipv6 anyway, which\n",
            "# blackholes v6 on the v4-only tun0 (broke Signal on the validated box).\n",
            "uci add_list openvpn.pia.pull_filter='ignore \"route-ipv6\"'\n",
            "uci add_list openvpn.pia.pull_filter='ignore \"ifconfig-ipv6\"'\n",
            "uci commit openvpn\n",
            "\n",
            "{ROUTE_BLOCK}",
            "# tun0 joins the vpn zone (wg0 was removed by the cleanup above)\n",
            "uci -q del_list firewall.vpn_zone.network='wg0'\n",
            "uci -q add_list firewall.vpn_zone.network='tun0'\n",
            "/etc/init.d/openvpn restart || /etc/init.d/openvpn start\n",
        ),
        CA = PIA_OPENVPN_CA,
        USERNAME = pia.username,
        PASSWORD = pia.password,
        REMOTE_LINES = remote_lines,
        ROUTE_BLOCK = route_block,
    );
    let payload = format!(
        "cat > /tmp/pia_openvpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/pia_openvpn_setup.sh",
        body.trim_end()
    );
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "openvpn-openssl".into(),
        },
        PlanOp::Shell { command: payload },
        // stale-section cleanup keeps re-runs idempotent (1.x
        // uci_cleanup_sections; the shared vpn-zone family name lets a
        // technology switch — wg → openvpn — retire the old rules)
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
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='Allow-VPN-Management'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_zone".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("REJECT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("tun0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_fwd".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("vpn".into())),
            ],
        },
    ];
    if pia.allow_management {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_mgmt".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-VPN-Management".into())),
                ("src".into(), literal("vpn".into())),
                ("proto".into(), literal("tcp".into())),
                ("dest_port".into(), literal("22 80 443".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        });
    }
    if pia.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_killswitch".into(),
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
    for dns in ["10.0.0.241", "10.0.0.242", "10.0.0.243"] {
        ops.push(PlanOp::Shell {
            command: format!("uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true"),
        });
        ops.push(PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: dns.into(),
        });
    }
    ops.push(PlanOp::SetUciOptions {
        config: "dhcp".into(),
        section: "@dnsmasq[0]".into(),
        options: vec![("noresolv".into(), literal("1".into()))],
    });
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "dhcp".into(),
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "dnsmasq".into(),
        action: ServiceAction::Restart,
    });
    if pia.kill_switch {
        // failure TAIL, not verification: a tunnel that never comes up
        // gets its kill switch REMOVED so a bad config cannot blackhole
        // the LAN (validated lesson)
        ops.push(PlanOp::Shell {
            command: "i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart".into(),
        });
    }
    // the 45s tail restores WAN on failure and exits 0 by design —
    // this check is what makes the apply HONEST about the outcome:
    // verified requires tun0 to actually hold an address (Codex #514
    // P2: auth failure / dead endpoints must not read as success)
    let verification = vec![
        VerificationCheck {
            description: "openvpn instance enabled".into(),
            command: "uci -q get openvpn.pia.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "tun0 has an address (tunnel actually up)".into(),
            command: "ip -4 addr show dev tun0 2>/dev/null | grep -q inet && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-pia-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

const NORD_JSON_HELPER_SH: &str = concat!(
    "# JSON parsing: try jq, install via apk (OpenWrt >=25.x) or opkg (<=24.x)\n",
    "if ! command -v jq >/dev/null 2>&1; then\n",
    "    apk add jq >/dev/null 2>&1 || { opkg update >/dev/null 2>&1 && opkg install jq >/dev/null 2>&1; }\n",
    "fi\n",
    "json_get() {\n",
    "    # $1 = key name; reads JSON from stdin; returns first string value\n",
    "    if command -v jq >/dev/null 2>&1; then\n",
    "        jq -r \".$1 // empty\"\n",
    "    else\n",
    "        tr -d '\\n' | sed \"s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*//\" | sed 's/[,\"].*//' | tr -d '\"'\n",
    "    fi\n",
    "}\n",
    "\n",
);
const NORD_GATEWAY_DISCOVER_SH: &str = concat!(
    "\n",
    "VPN_GW=\"\"\n",
    "_i=0\n",
    "# netifd's wireguard proto normally installs the endpoint /32 route itself on\n",
    "# ifup; this is a fallback for paths where it does not. Capped short because\n",
    "# uci-defaults block the boot sequence (dropbear starts only after).\n",
    "while [ $_i -lt 20 ]; do\n",
    "    VPN_GW=$(ip -4 route show default dev {iface} 2>/dev/null | head -n1 | sed -n 's/.*via \\\\([0-9.]\\\\+\\\\).*/\\\\1/p')\n",
    "    [ -z \"$VPN_GW\" ] && VPN_GW=$(ip -4 route show default 2>/dev/null | head -n1 | sed -n 's/.*via \\\\([0-9.]\\\\+\\\\).*/\\\\1/p')\n",
    "    [ -n \"$VPN_GW\" ] && break\n",
    "    sleep 2; _i=$((_i+2))\n",
    "done\n",
    "if [ -n \"$VPN_GW\" ]; then\n",
    "    uci -q delete network.nordvpn_server_route\n",
    "    uci set network.nordvpn_server_route=route\n",
    "    uci set network.nordvpn_server_route.interface='{iface}'\n",
    "    uci set network.nordvpn_server_route.target='{route_ip}'\n",
    "    uci set network.nordvpn_server_route.netmask='255.255.255.255'\n",
    "    uci set network.nordvpn_server_route.gateway=\"$VPN_GW\"\n",
    "    uci commit network\n",
    "    /etc/init.d/network reload >/dev/null 2>&1 || true\n",
    "    echo \"VPN: endpoint route {route_ip}/32 via $VPN_GW on {iface}\"\n",
    "else\n",
    "    echo \"VPN: WARNING no upstream gateway found — endpoint route skipped\"\n",
    "fi\n",
    "\n",
);

fn plan_vpn_nordvpn(model: &DeviceModel, nv: &VpnNordvpnProfile) -> Result<Plan, Unsupported> {
    nv.validate()?;
    let route_ip = nv.route_target.clone();
    // gateway set → static /32 route; empty → the bounded discovery
    // block (1.x _GATEWAY_DISCOVER_SH) that finds the default-route
    // gateway at apply time
    let route_block = if nv.upstream_gateway.is_empty() {
        NORD_GATEWAY_DISCOVER_SH
            .replace("{iface}", &nv.upstream_iface)
            .replace("{route_ip}", &route_ip)
    } else {
        format!(
            "uci set network.nordvpn_server_route=route\n\
             uci set network.nordvpn_server_route.interface='{iface}'\n\
             uci set network.nordvpn_server_route.target='{target}'\n\
             uci set network.nordvpn_server_route.netmask='255.255.255.255'\n\
             uci set network.nordvpn_server_route.gateway='{gateway}'\n",
            iface = nv.upstream_iface,
            target = route_ip,
            gateway = nv.upstream_gateway,
        )
    };
    // the payload rides ONE heredoc (1.x transport_sh): assignments are
    // double-quoted — validate()'s charsets are what make the verbatim
    // render safe
    let body = format!(
        concat!(
            "{JSON_HELPER}\n",
            "WG_PRIV=\"{PRIV}\"\n",
            "SERVER_KEY=\"{PUB}\"\n",
            "SERVER_IP=\"{HOST}\"\n",
            "\n",
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n",
            "\n",
            "uci -q delete openvpn.nordvpn\n",
            "/etc/init.d/openvpn stop >/dev/null 2>&1 || true\n",
            "\n",
            "# WireGuard tunnel (NordLynx)\n",
            "uci set network.wg0=interface\n",
            "uci set network.wg0.proto='wireguard'\n",
            "uci set network.wg0.private_key=\"$WG_PRIV\"\n",
            "uci add_list network.wg0.addresses='{ADDR}'\n",
            "uci set network.wg0.mtu='{MTU}'\n",
            "uci set network.wg0.auto='1'\n",
            "\n",
            "uci add network wireguard_wg0\n",
            "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
            "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
            "uci set network.@wireguard_wg0[0].endpoint_port='{PORT}'\n",
            "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
            "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
            "uci set network.@wireguard_wg0[0].persistent_keepalive='{KEEP}'\n",
            "\n",
            "\n",
            "uci -q delete network.nordvpn_server_route\n",
            "{ROUTE}",
        ),
        JSON_HELPER = NORD_JSON_HELPER_SH,
        PRIV = nv.private_key,
        PUB = nv.server_public_key,
        HOST = nv.endpoint_host,
        ADDR = nv.address,
        MTU = nv.mtu,
        PORT = nv.endpoint_port,
        KEEP = nv.keepalive,
        ROUTE = route_block,
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::Shell { command: payload },
        // shared vpn composition (byte-identical to the pia plan): the
        // family zone name lets technology switches retire old rules
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
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='Allow-VPN-Management'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_zone".into(),
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
            section: "vpn_fwd".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("vpn".into())),
            ],
        },
    ];
    if nv.allow_management {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_mgmt".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-VPN-Management".into())),
                ("src".into(), literal("vpn".into())),
                ("proto".into(), literal("tcp".into())),
                ("dest_port".into(), literal("22 80 443".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        });
    }
    if nv.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_killswitch".into(),
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
    for dns in ["103.86.96.100", "103.86.99.100"] {
        ops.push(PlanOp::Shell {
            command: format!("uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true"),
        });
        ops.push(PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: dns.into(),
        });
    }
    ops.push(PlanOp::SetUciOptions {
        config: "dhcp".into(),
        section: "@dnsmasq[0]".into(),
        options: vec![("noresolv".into(), literal("1".into()))],
    });
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "dhcp".into(),
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "dnsmasq".into(),
        action: ServiceAction::Restart,
    });
    if nv.kill_switch {
        // wg verify tail (30s handshake): failure REMOVES the kill
        // switch so a bad config cannot blackhole the LAN
        ops.push(PlanOp::Shell {
            command: "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart".into(),
        });
    }
    // honest outcome (the #514/#520 pattern): verified requires the
    // tunnel to actually hold a handshake — config-applied-but-dead
    // reports incomplete
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-nordvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_ssl(model: &DeviceModel, ssl: &SslProfile) -> Result<Plan, Unsupported> {
    ssl.validate()?;
    // libustream-{wolfssl,mbedtls,openssl} all own libustream-ssl.so —
    // installing wolfssl next to an existing backend is a file-clash
    // abort under `set -e` (Codex #486 round 5). ANY backend serves
    // uhttpd TLS, so the plan installs wolfssl only when NO
    // libustream provider is present and preserves the installed one
    // otherwise (1.x's hardcoded wolfssl list entry stays an
    // image-build choice, where a fresh image has no clash).
    let mut ops = vec![
        PlanOp::Shell {
            command: concat!(
                "if ! (opkg list-installed 2>/dev/null || apk info 2>/dev/null) ",
                "| grep -q '^libustream-'; then ",
                // manager-scoped install with the renderer's own
                // fresh-index self-heal (apk update && apk add) — the
                // retry never crosses into the other package manager
                "if command -v apk >/dev/null 2>&1; then ",
                "apk add libustream-wolfssl || { apk update && apk add libustream-wolfssl; }; ",
                "else opkg update && opkg install libustream-wolfssl; fi; fi",
            )
            .into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
    ];
    // Both branches are runtime-conditional payloads kept as SINGLE
    // `;`-joined lines: the 1.x transport (apply.py::_run_step_script)
    // routes any line-start `if` through a ` && ` line-join that would
    // mangle a multi-line block into invalid shell (`then && uci …`)
    // — a one-line conditional survives the join untouched. The
    // uhttpd wiring is guarded on the post-flash certs existing:
    // pointed at missing cert files uhttpd drops the HTTPS listener
    // or exits, so a cert-less router must not take the wiring yet
    // (Codex #486 P1 round 2). Each guard reverts its config's staged
    // /tmp/.uci debris first (AGENTS.md staging rule), the
    // listen_https reset stays idempotent (round-1 fix), and the
    // nodogsplash body uses del_list-before-add_list with no trailing
    // `|| true` (rounds 2+4 fixes: failures abort instead of masking
    // as success). The skip path must NOT read as success: with the
    // uhttpd branch enabled, verification requires the certs to exist
    // AND the uci readbacks to show the wiring — a cert-less device
    // fails the apply loudly instead of reporting `applied` for a
    // no-op (Codex #486 P1 round 3). The nds-only configuration keeps
    // no post-hoc checks: its outcome is genuinely runtime-conditional
    // on nodogsplash being installed.
    if ssl.enable_uhttpd_https {
        ops.push(PlanOp::Shell {
            command: concat!(
                "if [ -f /etc/tollgate/ssl/server.crt ] && ",
                "[ -f /etc/tollgate/ssl/server.key ]; then ",
                // &&-chained fail-fast body (the 1.x transport runs
                // control-flow scripts WITHOUT set -e — a `;` chain
                // would let a failed uci set ride a trailing echo to a
                // fake success). Best-effort steps (revert, delete)
                // are isolated in groups so `|| true` cannot swallow a
                // neighboring hard failure; the post-commit readback
                // gates the success echo.
                "(uci -q revert uhttpd 2>/dev/null || true) && ",
                "uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt' && ",
                "uci set uhttpd.main.key='/etc/tollgate/ssl/server.key' && ",
                "(uci -q delete uhttpd.main.listen_https || true) && ",
                "uci add_list uhttpd.main.listen_https='0.0.0.0:443' && ",
                "uci add_list uhttpd.main.listen_https='[::]:443' && ",
                "uci commit uhttpd && ",
                "uci -q get uhttpd.main.listen_https | grep -q '0.0.0.0:443' && ",
                "/etc/init.d/uhttpd restart && ",
                "echo 'ssl: uhttpd HTTPS wired on :443'; ",
                "else ",
                "echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2; ",
                "fi",
            )
            .into(),
        });
    }
    if ssl.open_port_443_nds {
        ops.push(PlanOp::Shell {
            command: concat!(
                "if uci -q show nodogsplash >/dev/null 2>&1; then ",
                "(uci -q revert nodogsplash 2>/dev/null || true) && ",
                "(uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' || true) && ",
                "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' && ",
                "uci commit nodogsplash && ",
                "uci -q get nodogsplash.@nodogsplash[0].users_to_router | grep -q 'allow tcp port 443' && ",
                "/etc/init.d/nodogsplash restart && ",
                "echo 'ssl: nodogsplash allows tcp/443 to the router'; ",
                "fi",
            )
            .into(),
        });
    }
    let mut verification = Vec::new();
    if ssl.enable_uhttpd_https {
        verification.extend([
            VerificationCheck {
                description: "certs deployed for uhttpd HTTPS (host-side post-flash step)".into(),
                command: "[ -f /etc/tollgate/ssl/server.crt ] && \
                          [ -f /etc/tollgate/ssl/server.key ] && echo present"
                    .into(),
                expect_contains: "present".into(),
            },
            VerificationCheck {
                description: "uhttpd cert path persisted".into(),
                command: "uci -q get uhttpd.main.cert".into(),
                expect_contains: "/etc/tollgate/ssl/server.crt".into(),
            },
            VerificationCheck {
                description: "uhttpd listens on 443".into(),
                command: "uci -q get uhttpd.main.listen_https".into(),
                expect_contains: "0.0.0.0:443".into(),
            },
        ]);
    }
    Ok(Plan {
        profile_id: "ssl".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_nodns(model: &DeviceModel, nd: &NodnsProfile) -> Result<Plan, Unsupported> {
    nd.validate()?;
    // curl is NOT in every base image (the preset's "no packages" claim
    // holds only where curl ships in base) — EnsurePackage it; the
    // golden comparator filters package lines, so parity is unaffected
    let mut ops: Vec<PlanOp> = vec![PlanOp::EnsurePackage {
        name: "curl".into(),
    }];
    let poll_script = NODNS_POLL_SCRIPT_TEMPLATE
        .replace("__URL__", &nd.api_url)
        .replace("__ZONE__", &nd.zone)
        .replace("__POLL_INTERVAL__", &nd.poll_interval.to_string());
    ops.extend([
        PlanOp::Shell {
            command: "mkdir -p /etc/dnsmasq.d".into(),
        },
        PlanOp::Shell {
            command: "touch /etc/dnsmasq.d/nodns.hosts".into(),
        },
        PlanOp::Shell {
            command: format!(
                "cat > /etc/init.d/nodns-bridge << 'NODNS_INIT_EOF'\n{NODNS_INITD_SCRIPT}NODNS_INIT_EOF"
            ),
        },
        PlanOp::Shell {
            command: "chmod +x /etc/init.d/nodns-bridge".into(),
        },
        PlanOp::Shell {
            command: format!(
                "cat > /usr/bin/nodns-poll.sh << 'NODNS_POLL_EOF'\n{poll_script}NODNS_POLL_EOF"
            ),
        },
        PlanOp::Shell {
            command: "chmod +x /usr/bin/nodns-poll.sh".into(),
        },
        PlanOp::Shell {
            command:
                "uci -q del_list dhcp.@dnsmasq[0].addnhosts='/etc/dnsmasq.d/nodns.hosts'; true"
                    .into(),
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "addnhosts".into(),
            value: "/etc/dnsmasq.d/nodns.hosts".into(),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Service {
            name: "nodns-bridge".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "nodns-bridge".into(),
            action: ServiceAction::Start,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"nodns bridge configured: zone={} interval={}s url={}\"",
                nd.zone, nd.poll_interval, nd.api_url
            ),
        },
    ]);
    let verification = vec![VerificationCheck {
        description: "dnsmasq addnhosts registered".into(),
        command: "uci -q get dhcp.@dnsmasq[0].addnhosts".into(),
        expect_contains: "/etc/dnsmasq.d/nodns.hosts".into(),
    }];
    Ok(Plan {
        profile_id: "nodns".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

fn plan_auto_sqm(model: &DeviceModel, asq: &AutoSqmProfile) -> Result<Plan, Unsupported> {
    asq.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = ["sqm-scripts", "luci-app-sqm", "jsonfilter", "iperf3"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell {
        command: "touch /etc/config/auto_sqm".into(),
    });
    ops.push(PlanOp::SetUciSection {
        config: "auto_sqm".into(),
        section: "config".into(),
        section_type: "auto_sqm".into(),
        options: vec![
            ("mode".into(), literal(asq.mode.clone())),
            ("interface".into(), literal(asq.interface.clone())),
            ("device".into(), literal(asq.device.clone())),
            (
                "target_percent".into(),
                literal(asq.target_percent.to_string()),
            ),
            ("qdisc".into(), literal(asq.qdisc.clone())),
            ("script".into(), literal(asq.script.clone())),
            (
                "measurement_mode".into(),
                literal(asq.measurement_mode.clone()),
            ),
            ("iperf3_host".into(), literal(asq.iperf3_host.clone())),
            ("iperf3_port".into(), literal(asq.iperf3_port.to_string())),
            ("test_url".into(), literal(asq.test_url.clone())),
            (
                "download_kbps".into(),
                literal(asq.download_kbps.to_string()),
            ),
            ("upload_kbps".into(), literal(asq.upload_kbps.to_string())),
            (
                "upload_fallback_kbps".into(),
                literal(asq.upload_fallback_kbps.to_string()),
            ),
            (
                "hysteresis_percent".into(),
                literal(asq.hysteresis_percent.to_string()),
            ),
            (
                "dynamic_interval_hours".into(),
                literal(asq.dynamic_interval_hours.to_string()),
            ),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "auto_sqm".into(),
    });
    ops.push(PlanOp::Shell {
        command: "cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm".into(),
    });
    // 1.x emits one Shell op per script line INCLUDING blanks — the
    // heredoc body must stay byte-faithful on-device (shell_lines
    // drops empties; that helper is for non-heredoc surfaces)
    for line in AUTO_SQM_SCRIPT.lines() {
        ops.push(PlanOp::Shell {
            command: line.into(),
        });
    }
    ops.push(PlanOp::Shell {
        command: "AUTO_SQM_EOF".into(),
    });
    ops.push(PlanOp::Shell {
        command: "chmod +x /usr/sbin/auto-sqm".into(),
    });
    ops.push(PlanOp::Shell {
        command: "mkdir -p /etc/hotplug.d/iface".into(),
    });
    ops.push(PlanOp::Shell {
        command: "cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune".into(),
    });
    ops.push(PlanOp::Shell {
        command: "#!/bin/sh".into(),
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "[ \"$ACTION\" = \"ifup\" ] && [ \"$INTERFACE\" = \"{}\" ] && /usr/sbin/auto-sqm &",
            asq.interface
        ),
    });
    ops.push(PlanOp::Shell {
        command: "HOTPLUG_EOF".into(),
    });
    ops.push(PlanOp::Shell {
        command: "chmod +x /etc/hotplug.d/iface/10-sqm-autotune".into(),
    });
    if asq.mode == "dynamic" {
        ops.push(PlanOp::Shell {
            // idempotent re-apply: drop any previous auto-sqm entry before
            // appending (plain append accumulates duplicate jobs — the
            // 1.x shape; comparator filters both line forms, unit-pinned)
            command: format!(
                "sed -i '/auto-sqm/d' /etc/crontabs/root 2>/dev/null; \
                 echo '0 */{} * * * /usr/sbin/auto-sqm' >> /etc/crontabs/root",
                asq.dynamic_interval_hours
            ),
        });
        ops.push(PlanOp::Service {
            name: "cron".into(),
            action: ServiceAction::Enable,
        });
        ops.push(PlanOp::Service {
            name: "cron".into(),
            action: ServiceAction::Restart,
        });
    }
    if asq.mode == "static" && asq.download_kbps > 0 {
        ops.push(PlanOp::Shell {
            command: "/usr/sbin/auto-sqm".into(),
        });
    } else {
        ops.push(PlanOp::Shell {
            command: "echo 'auto-sqm: will measure and configure on WAN ifup'".into(),
        });
    }
    ops.push(PlanOp::Shell {
        command: "echo 'Auto-SQM configured'".into(),
    });
    let verification = vec![VerificationCheck {
        description: "auto_sqm config persisted".into(),
        command: "uci -q get auto_sqm.config.mode".into(),
        expect_contains: asq.mode.clone(),
    }];
    Ok(Plan {
        profile_id: "auto-sqm".into(),
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
                // 1.x apk-aware shape (a11bfd6) + index self-heal: a fresh
                // 25.x boot may lack the apk adb index until `apk update`.
                // The opkg branch first checks `opkg list-installed`: a
                // device that already has the package must stay usable
                // offline — `opkg update` aborts under `set -e` when the
                // feed is unreachable (AGENTS.md package rules).
                script.push_str(&format!(
                    "if command -v apk >/dev/null 2>&1; then apk add {q} || {{ apk update \\
&& apk add {q}; }}; else [ -n \"$(opkg list-installed {q} 2>/dev/null)\" ] || {{ opkg update && opkg install {q}; }}; fi\n\n",
                    q = shell_quote(name)
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
                    ServiceAction::Start => "start",
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
    // Op-for-op mirror of the 1.x builder (`scripts/use_cases/sqm.py`
    // `_build_sqm_ops`), closing the parity GAP recorded in
    // tests/fixtures/parity/manifest.json:
    //
    // - no `RevertUci` step: 1.x has no revert; its clear-sections loop
    //   below already deletes every staged AND committed `queue` section
    //   (`uci show` displays the merged view) before the fresh values are
    //   staged, so leftover `/tmp/.uci` debris cannot survive the commit.
    // - device resolution, section creation, and the `interface=` line
    //   render as the exact 1.x one-line shell idioms (`_sqm_dev`), in
    //   1.x order: create → interface → values. A typed
    //   `ResolveNetworkDevice` op renders a multi-line if/fi block with a
    //   `_conwrt_dev_wan` variable — same semantics, different bytes.
    // - the final echo summary line is part of the 1.x contract.
    //
    // The `EnsurePackage` preamble stays: like wireguard/doh/tether, it is
    // a deliberate 2.x extension excluded from parity comparison by the
    // shared normalization (see `parity.rs::command_lines`), because 1.x
    // delivers packages out-of-band (`UseCase.packages` bakes them into
    // the image).
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "sqm-scripts".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-sqm".into(),
        },
        PlanOp::Shell {
            command: "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true".into(),
        },
        // Resolve UCI network name to actual linux device (e.g. wan →
        // phy1-sta0 on WiFi STA) — the 1.x `wan` lesson, 1.x shape.
        PlanOp::Shell {
            command: format!(
                "_sqm_dev=$(uci get network.{iface}.device 2>/dev/null || true); \
                 if [ -z \"$_sqm_dev\" ] || ! ip addr show \"$_sqm_dev\" 2>/dev/null | grep -q \"inet \"; then \
                 _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{{print $5}}' | head -1); fi; \
                 if [ -z \"$_sqm_dev\" ]; then _sqm_dev={iface}; fi"
            ),
        },
        PlanOp::Shell {
            command: format!("uci set sqm.{iface}=queue"),
        },
        // interface must be the actual device name, not a UCI network name
        PlanOp::Shell {
            command: format!("uci set sqm.{iface}.interface=\"$_sqm_dev\""),
        },
        PlanOp::SetUciOptions {
            config: "sqm".into(),
            section: iface.clone(),
            options: vec![
                ("enabled".into(), literal("1".into())),
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
        // 1.x closes with the human-facing summary on the resolved device
        PlanOp::Shell {
            command: format!(
                "echo \"SQM configured: {}/{} kbit/s ({}) on $_sqm_dev\"",
                sqm.download_kbps, sqm.upload_kbps, sqm.qdisc
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "shaper rate persisted exactly".into(),
            command: format!(
                "test \"$(uci -q get sqm.{iface}.download)\" = {rate} && echo ok",
                rate = shell_quote(&sqm.download_kbps.to_string())
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            // Scope to the shaped device: a global `tc qdisc show` is
            // satisfied by a matching qdisc on ANY interface (e.g. stale
            // state elsewhere), which would false-verify the apply.
            description: "qdisc active on the shaped device".into(),
            command: format!(
                "_d=$(uci get network.{iface}.device 2>/dev/null || true); \
                 if [ -z \"$_d\" ] || ! ip addr show \"$_d\" 2>/dev/null | grep -q 'inet '; then \
                 _d=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{{print $5}}' | head -1); fi; \
                 if [ -z \"$_d\" ]; then _d={iface}; fi; \
                 tc qdisc show dev \"$_d\""
            ),
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
        // package install covers both package managers; the opkg branch
        // must skip the (offline-failing) update for installed packages
        assert!(script.contains(
            "if command -v apk >/dev/null 2>&1; then apk add 'sqm-scripts' || { apk update"
        ));
        assert!(script.contains("opkg list-installed 'sqm-scripts' 2>/dev/null"));
        assert!(script.contains("|| { opkg update && opkg install 'sqm-scripts'; }; fi"));
        // clear-sections idiom, 1.x shape: one line, `done; true` joined
        assert!(script.contains(
            "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true"
        ));
        // device resolution is the 1.x one-line `_sqm_dev` idiom (not the
        // typed multi-line `_conwrt_dev_*` block), with the 2.x-only
        // `|| true` set -e guard
        assert!(script.contains(
            "_sqm_dev=$(uci get network.wan.device 2>/dev/null || true); if [ -z \"$_sqm_dev\" ]"
        ));
        assert!(script.contains("uci set sqm.wan.interface=\"$_sqm_dev\""));
        // 1.x option order: interface directly after section creation,
        // before enabled
        let interface_at = script
            .find("uci set sqm.wan.interface=")
            .expect("interface line");
        let enabled_at = script
            .find("uci set sqm.wan.enabled=")
            .expect("enabled line");
        let create_at = script.find("uci set sqm.wan=queue").expect("creation line");
        assert!(create_at < interface_at && interface_at < enabled_at);
        // single-quoted literals, 1.x convention
        assert!(script.contains("uci set sqm.wan.download='340000'"));
        assert!(script.contains("uci set sqm.wan.upload='19000'"));
        assert!(script.contains("uci commit sqm"));
        assert!(script.contains("/etc/init.d/sqm enable"));
        assert!(script.contains("/etc/init.d/sqm restart"));
        // 1.x closes with the echo summary on the resolved device
        assert!(
            script.contains("echo \"SQM configured: 340000/19000 kbit/s (cake) on $_sqm_dev\"")
        );
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
    fn doh_validation_rejects_port_zero() {
        let model = model_with_capabilities(None);
        let refused = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Doh(DohProfile {
                provider: "cloudflare".into(),
                listen_port: 0,
            }),
        );
        assert!(
            matches!(refused, Err(Unsupported::InvalidParams(_))),
            "port 0 must never plan 127.0.0.1#0"
        );
        let ok = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Doh(DohProfile {
                provider: "cloudflare".into(),
                listen_port: 5053,
            }),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn sqm_verification_targets_the_shaped_device_exactly() {
        let model = model_with_capabilities(None);
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Sqm(test_sqm_defaults()),
        )
        .expect("plans");
        let qdisc = plan
            .verification
            .iter()
            .find(|c| c.description.contains("qdisc"))
            .expect("qdisc check");
        // scoped to one resolved device, never a global `tc qdisc show`
        assert!(qdisc.command.contains("tc qdisc show dev \"$_d\""));
        assert_ne!(qdisc.command, "tc qdisc show");
        let rate = plan
            .verification
            .iter()
            .find(|c| c.description.contains("rate"))
            .expect("rate check");
        // exact equality, not a substring that 110000 would also satisfy
        assert!(
            rate.command
                .starts_with("test \"$(uci -q get sqm.wan.download)\" = '10000'")
        );
    }

    #[test]
    fn doh_verification_uses_exact_predicates() {
        let model = model_with_capabilities(None);
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Doh(DohProfile {
                provider: "cloudflare".into(),
                listen_port: 5053,
            }),
        )
        .expect("plans");
        let resolver = plan
            .verification
            .iter()
            .find(|c| c.description.contains("resolver"))
            .expect("resolver check");
        assert!(
            resolver
                .command
                .starts_with("test \"$(uci -q get https-dns-proxy.main.resolver_url)\" = ")
        );
        let forward = plan
            .verification
            .iter()
            .find(|c| c.description.contains("dnsmasq"))
            .expect("forward check");
        assert!(forward.command.contains("grep -qx '127.0.0.1#5053'"));
    }

    #[test]
    fn sqm_plan_mirrors_1x_builder_op_stream() {
        let model = model_with_capabilities(None);
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model,
            &Profile::Sqm(test_sqm_defaults()),
        )
        .expect("plans");
        let script = render_shell(&plan);
        // 1.x has no revert step: its clear-sections loop already deletes
        // every staged AND committed queue section (uci show displays the
        // merged view) before fresh values are staged, so /tmp/.uci debris
        // cannot survive the commit.
        assert!(
            !script.contains("uci revert"),
            "1.x parity: no revert step, the clear loop is the baseline reset:\n{script}"
        );
        // clear loop precedes the first sqm mutation
        let clear_pos = script
            .find("uci -q show sqm")
            .expect("script clears sqm sections");
        let first_mutation = script.find("uci set sqm").expect("script mutates sqm");
        assert!(
            clear_pos < first_mutation,
            "clear must precede the first sqm mutation:\n{script}"
        );
        // the echo summary is the final command line of the script body
        let lines: Vec<&str> = script
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && t != "set -e"
            })
            .collect();
        assert_eq!(
            lines.last(),
            Some(&"echo \"SQM configured: 10000/5000 kbit/s (cake) on $_sqm_dev\""),
            "1.x closes with the SQM summary echo"
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
    fn ssh_hardening_default_and_flipped_branches_match_1x() {
        let default_script = render_shell(&plan_for(Profile::SshHardening(
            SshHardeningProfile::default(),
        )));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].PasswordAuth='off'"));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].RootPasswordAuth='off'"));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].Port='22'"));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].IdleTimeout='300'"));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].MaxAuthTries='3'"));
        assert!(default_script.contains("uci set dropbear.@dropbear[0].GatewayPorts='no'"));
        assert!(default_script.contains("uci commit dropbear"));
        assert!(default_script.contains("/etc/init.d/dropbear restart"));
        assert!(
            default_script
                .contains("echo \"SSH hardened: password_auth=off idle=300s max_tries=3 port=22\"")
        );

        let flipped = render_shell(&plan_for(Profile::SshHardening(SshHardeningProfile {
            disable_password_auth: false,
            idle_timeout: 0,
            max_auth_tries: 1,
            port: 2222,
            restrict_gateway_ports: false,
        })));
        assert!(flipped.contains("uci set dropbear.@dropbear[0].PasswordAuth='on'"));
        assert!(flipped.contains("uci set dropbear.@dropbear[0].GatewayPorts='yes'"));
        assert!(flipped.contains("uci set dropbear.@dropbear[0].IdleTimeout='0'"));
        assert!(
            flipped
                .contains("echo \"SSH hardened: password_auth=on idle=0s max_tries=1 port=2222\"")
        );
    }

    #[test]
    fn travelmate_branches_and_capability_gate_match_1x() {
        let default_script =
            render_shell(&plan_for(Profile::Travelmate(TravelmateProfile::default())));
        assert!(default_script.contains("uci set travelmate.global.trm_enabled='1'"));
        assert!(default_script.contains("uci set travelmate.global.trm_captive='1'"));
        assert!(default_script.contains("uci set travelmate.global.trm_timeout='60'"));
        assert!(default_script.contains("uci set travelmate.global.trm_retry='5'"));
        assert!(default_script.contains("uci set travelmate.global.trm_radio='radio0'"));
        assert!(default_script.contains("uci commit travelmate"));
        assert!(default_script.contains("/etc/init.d/travelmate enable"));
        assert!(default_script.contains("/etc/init.d/travelmate restart"));
        assert!(default_script.contains("echo \"Travelmate configured: auto-connect on radio0\""));

        let flipped = render_shell(&plan_for(Profile::Travelmate(TravelmateProfile {
            radio: "radio1".into(),
            timeout: 30,
            retry: 2,
            captive: false,
            ..TravelmateProfile::default()
        })));
        assert!(flipped.contains("uci set travelmate.global.trm_captive='0'"));
        assert!(flipped.contains("uci set travelmate.global.trm_timeout='30'"));
        assert!(flipped.contains("uci set travelmate.global.trm_retry='2'"));
        assert!(flipped.contains("uci set travelmate.global.trm_radio='radio1'"));
        assert!(flipped.contains("echo \"Travelmate configured: auto-connect on radio1\""));

        // wifi capability gate (1.x requires_capabilities=["wifi"])
        let no_wifi = conwrt_types::DeviceModel {
            id: "no-wifi".into(),
            vendor: "Test".into(),
            description: "d".into(),
            openwrt: conwrt_types::OpenwrtInfo {
                target: "x/y".into(),
                device: "t,d".into(),
                profile: "t_d".into(),
                version: "24".into(),
                board_name: None,
                board_names: None,
                default_ip: None,
                extras: Default::default(),
            },
            capabilities: Some(vec!["ethernet".into()]),
            flash_methods: None,
            mac_oui: Vec::new(),
            serial_console: None,
            warnings: None,
            extras: Default::default(),
        };
        assert!(matches!(
            plan_profile(&DeviceState::OpenWrt, &no_wifi, &Profile::Travelmate(TravelmateProfile::default())),
            Err(Unsupported::MissingCapability { capability, .. }) if capability == "wifi"
        ));
    }

    #[test]
    fn travelmate_uplink_seeding_renders_sta_profiles() {
        let plan = plan_for(Profile::Travelmate(TravelmateProfile {
            uplinks: vec![
                WifiUplink {
                    ssid: "home-net".into(),
                    psk: "hunter2 son".into(),
                    encryption: "psk2".into(),
                    radio: "radio1".into(),
                    iface: "trm_uplink1".into(),
                },
                WifiUplink {
                    ssid: "cafe open".into(),
                    psk: String::new(),
                    encryption: "none".into(),
                    radio: "radio0".into(),
                    iface: "trm_uplink2".into(),
                },
            ],
            ..TravelmateProfile::default()
        }));
        let script = render_shell(&plan);
        assert!(script.contains("uci set travelmate.global.trm_iface='trm_wwan'"));
        assert!(script.contains("uci set travelmate.global.trm_uplink='trm_wwan'"));
        assert!(script.contains("uci set network.trm_wwan=interface"));
        assert!(script.contains("uci set network.trm_wwan.proto='dhcp'"));
        assert!(script.contains("uci set network.trm_wwan.metric='100'"));
        assert!(script.contains("uci set network.trm_wwan6=interface"));
        assert!(script.contains("uci set network.trm_wwan6.device='@trm_wwan'"));
        assert!(script.contains("uci set network.trm_wwan6.proto='dhcpv6'"));
        // the 1.x wan-zone helper (del_list-then-add_list on the NAME-matched zone), both ifaces
        assert!(script.contains("uci add_list firewall.\"$_z\".network='trm_wwan'"));
        assert!(script.contains("uci add_list firewall.\"$_z\".network='trm_wwan6'"));
        assert!(script.contains("uci set wireless.trm_uplink1=wifi-iface"));
        assert!(script.contains("uci set wireless.trm_uplink1.device='radio1'"));
        assert!(script.contains("uci set wireless.trm_uplink1.mode='sta'"));
        assert!(script.contains("uci set wireless.trm_uplink1.network='trm_wwan'"));
        assert!(script.contains("uci set wireless.trm_uplink1.ssid='home-net'"));
        assert!(script.contains("uci set wireless.trm_uplink1.encryption='psk2'"));
        assert!(script.contains("uci set wireless.trm_uplink1.key='hunter2 son'"));
        // travelmate recognition pairs: uplink sections in its own config
        assert!(script.contains("uci set travelmate.trm_uplink1=uplink"));
        assert!(script.contains("uci set travelmate.trm_uplink1.device='radio1'"));
        assert!(script.contains("uci set travelmate.trm_uplink1.enabled='1'"));
        assert!(script.contains("uci set travelmate.trm_uplink2=uplink"));
        assert!(script.contains("uci set travelmate.trm_uplink2.enabled='1'"));
        // open network: no key option at all
        assert!(script.contains("uci set wireless.trm_uplink2.ssid='cafe open'"));
        assert!(script.contains("uci set wireless.trm_uplink2.encryption='none'"));
        assert!(!script.contains("trm_uplink2.key"));
        assert!(script.contains("uci commit wireless"));
        assert!(script.contains("wifi reload; ubus call network.interface.trm_wwan up"));
        // secrets stay single-quote-escaped, never interpolated raw
        let hostile = plan_for(Profile::Travelmate(TravelmateProfile {
            uplinks: vec![WifiUplink {
                ssid: "ev'; rm -rf /; '".into(),
                psk: "p'w".into(),
                encryption: "psk2".into(),
                radio: "radio0".into(),
                iface: "trm_uplink3".into(),
            }],
            ..TravelmateProfile::default()
        }));
        let hostile_script = render_shell(&hostile);
        assert!(
            hostile_script.contains("uci set wireless.trm_uplink3.ssid='ev'\\''; rm -rf /; '\\''")
        );
        assert!(hostile_script.contains("uci set wireless.trm_uplink3.key='p'\\''w'"));
    }

    #[test]
    fn travelmate_without_uplinks_stays_1x_shape() {
        let script = render_shell(&plan_for(Profile::Travelmate(TravelmateProfile::default())));
        assert!(!script.contains("trm_iface"));
        assert!(!script.contains("wifi-iface"));
        assert!(!script.contains("trm_wwan"));
    }

    #[test]
    fn sqm_resolve_survives_set_e_when_wan_device_is_absent() {
        // the 2.x preamble is `set -e` (1.x runs bare); an unguarded
        // `var=$(uci get ...)` kills the whole script under `sh -c`
        // exec when the option is missing — found live via
        // `conwrt apply --execute` on a fixture VM without wan.device.
        let script = render_shell(&plan_for(Profile::Sqm(test_sqm_defaults())));
        assert!(
            script.contains("_sqm_dev=$(uci get network.wan.device 2>/dev/null || true)"),
            "resolve substitution must be set -e safe"
        );
    }

    #[test]
    fn adguard_default_and_custom_render_match_1x_shape() {
        let script = render_shell(&plan_for(Profile::Adguard(AdguardProfile::default())));
        assert!(script.contains("uci set adguardhome.adguardhome=adguardhome"));
        assert!(script.contains("uci set adguardhome.adguardhome.enabled='1'"));
        assert!(script.contains("uci set adguardhome.adguardhome.http_address='0.0.0.0:3000'"));
        assert!(script.contains("uci set adguardhome.adguardhome.dns_port='5353'"));
        assert!(script.contains("uci commit adguardhome"));
        assert!(script.contains("/etc/init.d/adguardhome enable"));
        assert!(script.contains("/etc/init.d/adguardhome start"));
        assert!(script.contains("uci set dhcp.@dnsmasq[0].noresolv='1'"));
        assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'"));
        assert!(script.contains("uci commit dhcp"));
        assert!(script.contains("/etc/init.d/dnsmasq restart"));
        assert!(script.contains(
            "echo \"AdGuard Home configured: DNS on port 5353, web UI at 0.0.0.0:3000\""
        ));

        let custom = render_shell(&plan_for(Profile::Adguard(AdguardProfile {
            listen_ip: "192.168.1.1".into(),
            web_port: 8080,
            dns_port: 5333,
        })));
        assert!(custom.contains("uci set adguardhome.adguardhome.http_address='192.168.1.1:8080'"));
        assert!(custom.contains("uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5333'"));
        assert!(custom.contains("web UI at 192.168.1.1:8080"));
    }

    #[test]
    fn mesh11sd_key_branch_order_and_required_gate_match_1x() {
        let no_key = render_shell(&plan_for(Profile::Mesh11sd(Mesh11sdProfile {
            mesh_id: "testmesh".into(),
            ..Mesh11sdProfile::default()
        })));
        assert!(no_key.contains("uci set mesh11sd.setup.auto_mesh_id='testmesh'"));
        assert!(no_key.contains("uci set mesh11sd.setup.mesh_gate_base_ssid='MeshNet'"));
        assert!(no_key.contains("uci set mesh11sd.setup.mesh_gate_encryption='1'"));
        assert!(no_key.contains("uci set mesh11sd.setup.auto_config='0'"));
        assert!(!no_key.contains("mesh_gate_key"));
        assert!(no_key.contains("uci commit mesh11sd"));
        assert!(no_key.contains("service mesh11sd restart 2>/dev/null || true"));
        assert!(no_key.contains("echo \"Mesh11sd configured: mesh_id=testmesh ssid=MeshNet\""));

        let with_key = render_shell(&plan_for(Profile::Mesh11sd(Mesh11sdProfile {
            mesh_id: "m2".into(),
            ssid: "Backhaul".into(),
            encryption: "3".into(),
            key: "mesh pass".into(),
            auto_config: "2".into(),
        })));
        // 1.x dict insertion order: key BETWEEN encryption and auto_config
        let enc = with_key.find("mesh_gate_encryption='3'").expect("enc");
        let key = with_key.find("mesh_gate_key='mesh pass'").expect("key");
        let auto = with_key.find("auto_config='2'").expect("auto");
        assert!(enc < key && key < auto, "1.x option order must hold");

        // required-param gate
        assert!(matches!(
            Mesh11sdProfile::default().validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn rescue_watchdog_payload_is_verbatim_with_target_substituted() {
        let script = render_shell(&plan_for(Profile::RescueWatchdog(RescueWatchdogProfile {
            target: "192.168.105.10".into(),
        })));
        assert!(script.contains("cat > /etc/init.d/rescue-watchdog << 'WD_EOF'"));
        assert!(script.contains("procd_set_param respawn 3600 5 0"));
        assert!(script.contains("TARGET=\"${WATCHDOG_TARGET:-192.168.105.10}\""));
        assert!(script.contains("[ \"$FAILS\" -ge 3 ]"));
        assert!(script.contains("/etc/init.d/rescue-watchdog enable"));
        // no unsubstituted placeholder survives
        assert!(!script.contains("__TARGET__"));
    }

    #[test]
    fn mwan3_shape_members_policy_rules_and_track_ip_fix() {
        let script = render_shell(&plan_for(Profile::Mwan3(Mwan3Profile::default())));
        assert!(script.contains("uci -q delete mwan3 >/dev/null 2>&1 || true"));
        assert!(script.contains("uci set mwan3.wan=interface"));
        assert!(script.contains("uci set mwan3.wan.enabled='1'"));
        // the 1.x `list track_ip` defect is FIXED: real add_list ops per section
        assert!(script.contains("uci add_list mwan3.wan.track_ip='1.0.0.1'"));
        assert!(script.contains("uci add_list mwan3.usbwan.track_ip='8.8.4.4'"));
        assert!(!script.contains("list track_ip"));
        assert!(script.contains("uci set mwan3.wan.family='ipv4'"));
        assert!(script.contains("uci set mwan3.usbwan=interface"));
        // failover metrics: primary m1w1, secondary m2w1
        assert!(script.contains("uci set mwan3.wan_m1_w1=member"));
        assert!(script.contains("uci set mwan3.usbwan_m2_w1=member"));
        assert!(script.contains("uci set mwan3.wan_policy=policy"));
        assert!(script.contains("uci add_list mwan3.wan_policy.use_member='wan_m1_w1'"));
        assert!(script.contains("uci add_list mwan3.wan_policy.use_member='usbwan_m2_w1'"));
        assert!(script.contains("uci set mwan3.wan_policy.last_resort='default'"));
        assert!(script.contains("uci set mwan3.default_rule_v4=rule"));
        assert!(
            script.contains(
                "uci set mwan3.https_rule.rule"
                    .replace(".rule", "=rule")
                    .as_str()
            )
        );
        assert!(script.contains("uci commit mwan3"));
        assert!(script.contains("/etc/init.d/mwan3 restart"));
        assert!(script.contains("echo \"mwan3 configured: wan (primary) + usbwan (failover)\""));

        // balanced flips the metrics/weights; non-default primary gets its
        // own tracked section (1.x hardcoded `wan` — Codex #448 P1)
        let balanced = render_shell(&plan_for(Profile::Mwan3(Mwan3Profile {
            primary: "wwan2".into(),
            secondary: "wwan".into(),
            policy: "balanced".into(),
            track_ips: vec!["9.9.9.9".into()],
        })));
        assert!(balanced.contains("uci set mwan3.wwan2=interface"));
        assert!(balanced.contains("uci set mwan3.wwan2_m1_w2=member"));
        assert!(balanced.contains("uci set mwan3.wwan_m1_w1=member"));
        assert!(balanced.contains("uci add_list mwan3.wwan.track_ip='9.9.9.9'"));

        // interface_name charset gate
        assert!(matches!(
            Mwan3Profile {
                primary: "wan; rm".into(),
                ..Mwan3Profile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // policy is interpolated into the echo line — hostile values refused
        assert!(matches!(
            Mwan3Profile {
                policy: "x'; rm -rf /; '".into(),
                ..Mwan3Profile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn pbr_shape_gates_and_strict_branch_match_1x() {
        let script = render_shell(&plan_for(Profile::Pbr(PbrProfile::default())));
        assert!(script.contains("uci set pbr.config=pbr"));
        assert!(script.contains("uci set pbr.config.enabled='1'"));
        assert!(script.contains("uci set pbr.config.verbosity='2'"));
        assert!(script.contains("uci set pbr.config.strict_enforcement='1'"));
        assert!(script.contains("uci set pbr.config.resolver_set='none'"));
        assert!(script.contains("uci set pbr.config.nft_file_helper='1'"));
        // 1.x renders the interface wiring UNQUOTED (byte parity); the
        // validate() charset gate is the safety story for these bytes
        assert!(script.contains("uci set pbr.config.netifd_interface_default=wan"));
        assert!(script.contains("uci add_list pbr.config.netifd_interface_local=lan"));
        assert!(script.contains("uci commit pbr"));
        assert!(script.contains("/etc/init.d/pbr enable"));
        assert!(script.contains("/etc/init.d/pbr restart"));
        assert!(
            script.contains(
                "echo \"pbr configured. Verify with: nft list table inet pbr 2>/dev/null\""
            )
        );
        assert!(script.contains("echo \"Check status: /etc/init.d/pbr status\""));

        // strict off flips the enforcement bit; custom interfaces ride
        // the same unquoted lines
        let lenient = render_shell(&plan_for(Profile::Pbr(PbrProfile {
            wan_interface: "wwan".into(),
            lan_interface: "guest".into(),
            strict_enforcement: false,
        })));
        assert!(lenient.contains("uci set pbr.config.strict_enforcement='0'"));
        assert!(lenient.contains("uci set pbr.config.netifd_interface_default=wwan"));
        assert!(lenient.contains("uci add_list pbr.config.netifd_interface_local=guest"));

        // interface_name charset gate (both directions of the wiring)
        assert!(matches!(
            PbrProfile {
                wan_interface: "wan; rm -rf /".into(),
                ..PbrProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            PbrProfile {
                lan_interface: "$(reboot)".into(),
                ..PbrProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn openclash_shape_gates_and_branches_match_1x() {
        let plan = plan_for(Profile::OpenClash(OpenClashProfile::default()));
        let script = render_shell(&plan);
        // dnsmasq→dnsmasq-full swap rides the plan AND LEADS the
        // package installs (Codex #486 rounds 1+4): luci-app-openclash
        // depends on dnsmasq-full, so on an opkg device with default
        // dnsmasq the swap must complete before the dependent resolves.
        // Download-first (round 6): a dead feed aborts BEFORE the
        // removal, never leaving the router without dnsmasq.
        let swap = plan
            .ops
            .iter()
            .position(|op| matches!(op, PlanOp::Shell { command } if command.starts_with("if [ -n \"$(opkg list-installed dnsmasq")))
            .expect("swap op present");
        let full = plan
            .ops
            .iter()
            .position(|op| matches!(op, PlanOp::EnsurePackage { name } if name == "dnsmasq-full"))
            .expect("dnsmasq-full install present");
        let luci = plan
            .ops
            .iter()
            .position(
                |op| matches!(op, PlanOp::EnsurePackage { name } if name == "luci-app-openclash"),
            )
            .expect("luci-app-openclash install present");
        assert!(
            swap < full && full < luci,
            "swap must precede dnsmasq-full, which must precede luci-app-openclash"
        );
        assert!(script.contains("opkg download dnsmasq-full) && opkg remove dnsmasq"));
        // staged /tmp/.uci debris reverted before the first mutation
        assert!(script.contains("uci -q revert openclash 2>/dev/null || true"));
        assert!(script.contains("mkdir -p /etc/openclash/config"));
        assert!(script.contains("uci set openclash.config.enable='1'"));
        assert!(
            script.contains(
                "uci set openclash.config.config_path='/etc/openclash/config/config.yaml'"
            )
        );
        assert!(script.contains("uci set openclash.config.proxy_type='ss'"));
        assert!(script.contains("uci set openclash.config.core_type='Meta'"));
        assert!(script.contains("uci set openclash.config.dashboard_type='Official'"));
        assert!(script.contains("uci set openclash.config.dns_mode='redir-host'"));
        assert!(script.contains("uci set openclash.config.operation_mode='redir-host'"));
        assert!(script.contains("uci commit openclash"));
        assert!(script.contains("/etc/init.d/openclash enable"));
        assert!(script.contains("echo \"OpenClash configured: Meta core, ss proxy\""));
        assert!(
            script.contains(
                "echo \"Post-flash: import your subscription config via the LuCI web UI\""
            )
        );

        // custom params ride the same lines; operation_mode mirrors dns_mode
        let custom = render_shell(&plan_for(Profile::OpenClash(OpenClashProfile {
            proxy_type: "trojan".into(),
            core_type: "Tun".into(),
            dns_mode: "fake-ip".into(),
        })));
        assert!(custom.contains("uci set openclash.config.proxy_type='trojan'"));
        assert!(custom.contains("uci set openclash.config.core_type='Tun'"));
        assert!(custom.contains("uci set openclash.config.dns_mode='fake-ip'"));
        assert!(custom.contains("uci set openclash.config.operation_mode='fake-ip'"));
        assert!(custom.contains("echo \"OpenClash configured: Tun core, trojan proxy\""));

        // token charset gate on every interpolated param (the
        // double-quoted echo is the hole this closes — mwan3/#448 class)
        for (field, hostile_value) in [
            ("proxy_type", "ss\"; reboot; echo \""),
            ("core_type", "$(poweroff)"),
            ("dns_mode", "redir-host\nreboot"),
            ("proxy_type", ""),
        ] {
            let mut hostile = OpenClashProfile::default();
            match field {
                "proxy_type" => hostile.proxy_type = hostile_value.into(),
                "core_type" => hostile.core_type = hostile_value.into(),
                _ => hostile.dns_mode = hostile_value.into(),
            }
            assert!(
                matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
                "{field} gate must reject {hostile_value:?}"
            );
        }
    }

    #[test]
    fn ssl_shape_branches_and_provider_gate_match_1x() {
        let plan = plan_for(Profile::Ssl(SslProfile::default()));
        let script = render_shell(&plan);
        // TLS-backend guard (Codex #486 round 5): the libustream
        // variants own the same libustream-ssl.so, so wolfssl installs
        // ONLY when no backend is present — an existing
        // mbedtls/openssl backend is preserved, never clashed
        assert!(script.contains("| grep -q '^libustream-'"));
        assert!(script.contains("opkg install libustream-wolfssl"));
        assert!(!plan.ops.iter().any(|op| matches!(
            op,
            PlanOp::EnsurePackage { name } if name == "libustream-wolfssl"
        )));
        assert!(plan.ops.iter().any(|op| matches!(
            op,
            PlanOp::EnsurePackage { name } if name == "ca-bundle"
        )));
        // cert-presence guard wraps the whole uhttpd block (Codex #486
        // P1 round 2): a cert-less router skips the wiring loudly
        // instead of pointing uhttpd at missing files
        assert!(script.contains(
            "if [ -f /etc/tollgate/ssl/server.crt ] && [ -f /etc/tollgate/ssl/server.key ]; then"
        ));
        assert!(script.contains("uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'"));
        assert!(script.contains("uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'"));
        // idempotent listen_https reset (round-1 fix): the delete is
        // guarded so an HTTP-only config still gets both listeners
        assert!(script.contains("uci -q delete uhttpd.main.listen_https || true"));
        assert!(script.contains("uci add_list uhttpd.main.listen_https='0.0.0.0:443'"));
        assert!(script.contains("uci add_list uhttpd.main.listen_https='[::]:443'"));
        assert!(!script.contains("listen_https &&"));
        assert!(script.contains("uci commit uhttpd"));
        assert!(script.contains("/etc/init.d/uhttpd restart"));
        assert!(script.contains("echo 'ssl: uhttpd HTTPS wired on :443'"));
        // staged /tmp/.uci debris reverted inside each guard before
        // the first mutation (AGENTS.md staging rule)
        assert!(script.contains("uci -q revert uhttpd 2>/dev/null || true"));
        assert!(script.contains("uci -q revert nodogsplash 2>/dev/null || true"));
        assert!(script.contains(
            "echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2"
        ));
        // explicit nodogsplash existence guard with a propagating body
        // (Codex #486 P2 round 2): failures abort instead of riding a
        // trailing `|| true` to a fake success
        assert!(script.contains("if uci -q show nodogsplash >/dev/null 2>&1; then"));
        // del_list-before-add_list keeps re-runs idempotent (Codex #486
        // round 4): uci lists are append-only
        assert!(script.contains(
            "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' || true"
        ));
        assert!(script.contains(
            "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443'"
        ));
        assert!(!script.contains("nodogsplash restart || true"));
        assert!(script.contains("echo 'ssl: nodogsplash allows tcp/443 to the router'"));

        // cert-less skip must FAIL the apply, not report `applied` for
        // a no-op (Codex #486 round 3): outcome verification gates on
        // certs existing plus the uci readbacks
        let plan = plan_for(Profile::Ssl(SslProfile::default()));
        let descriptions: Vec<&str> = plan
            .verification
            .iter()
            .map(|c| c.description.as_str())
            .collect();
        assert!(
            descriptions.contains(&"certs deployed for uhttpd HTTPS (host-side post-flash step)")
        );
        assert!(descriptions.contains(&"uhttpd cert path persisted"));
        assert!(descriptions.contains(&"uhttpd listens on 443"));
        // nds-only shape keeps no post-hoc checks (runtime-conditional
        // outcome when nodogsplash is absent)
        let nds_only = plan_for(Profile::Ssl(SslProfile {
            enable_uhttpd_https: false,
            ..SslProfile::default()
        }));
        assert!(nds_only.verification.is_empty());

        // uhttpd off drops the whole HTTPS block, keeps the nds line
        let no_uhttpd = render_shell(&plan_for(Profile::Ssl(SslProfile {
            enable_uhttpd_https: false,
            ..SslProfile::default()
        })));
        assert!(!no_uhttpd.contains("uhttpd"));
        assert!(no_uhttpd.contains("nodogsplash"));

        // nds off drops only the nodogsplash line
        let no_nds = render_shell(&plan_for(Profile::Ssl(SslProfile {
            open_port_443_nds: false,
            ..SslProfile::default()
        })));
        assert!(no_nds.contains("uci commit uhttpd"));
        assert!(!no_nds.contains("nodogsplash"));

        // provider choice gate — 1.x declared the choices but never
        // enforced them in _resolve_params (newline injection into the
        // comment line was live shell)
        assert!(matches!(
            SslProfile {
                provider: "lancert\nreboot".into(),
                ..SslProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SslProfile {
                provider: "evil".into(),
                ..SslProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        for ok in ["lancert", "qip", "manual"] {
            assert!(
                SslProfile {
                    provider: ok.into(),
                    ..SslProfile::default()
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn vpn_nordvpn_shape_gates_and_branches_match_1x() {
        let base = VpnNordvpnProfile {
            private_key: "STUBPRIVKEYbase64filledfortestonly0000=".into(),
            server_public_key: "STUBPUBKEYbase64filledfortestonly0000=".into(),
            endpoint_host: "de500.nordvpn.com".into(),
            route_target: "193.29.107.10".into(),
            upstream_gateway: "192.168.8.1".into(),
            ..VpnNordvpnProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnNordvpn(base.clone())));
        // heredoc payload + the resolved statics riding double-quoted
        // assignments (validate()'s charsets gate them)
        assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
        assert!(script.contains("WG_PRIV=\"STUBPRIVKEYbase64filledfortestonly0000=\""));
        // the endpoint /32 pin uses the RESOLVED route target, not the hostname
        assert!(script.contains("nordvpn_server_route.target='193.29.107.10'"));
        // wg tunnel + 30s handshake verify tail
        assert!(script.contains("uci set network.wg0.proto='wireguard'"));
        assert!(script.contains("wg show wg0 2>/dev/null | grep -q 'latest handshake'"));
        // NordVPN DNS pair
        assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='103.86.99.100'"));

        // empty gateway swaps the static pin for the bounded discovery block
        let discover = render_shell(&plan_for(Profile::VpnNordvpn(VpnNordvpnProfile {
            upstream_gateway: String::new(),
            ..base.clone()
        })));
        assert!(discover.contains("VPN_GW=$(ip -4 route show default dev wwan"));
        assert!(!discover.contains("gateway='192.168.8.1'"));

        // gates: base64 keys, resolved-IP route target, numeric fields,
        // CIDR address, host-or-ip endpoint, iface charset
        for hostile in [
            VpnNordvpnProfile {
                private_key: "line1\nline2".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                server_public_key: "$(reboot)".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                route_target: String::new(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                route_target: "not-an-ip".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                endpoint_host: "de; poweroff".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                endpoint_port: "51820; reboot".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                address: "10.5.0.2".into(),
                ..base.clone()
            },
            VpnNordvpnProfile {
                upstream_iface: "wwan; x".into(),
                ..base
            },
        ] {
            assert!(
                matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
                "gate must reject {hostile:?}"
            );
        }
    }

    #[test]
    fn vpn_pia_openvpn_shape_gates_and_branches_match_1x() {
        let plan = plan_for(Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
            username: "p1234567".into(),
            password: "testpass".into(),
            upstream_gateway: "192.168.8.1".into(),
            ..VpnPiaOpenvpnProfile::default()
        }));
        let script = render_shell(&plan);
        // one heredoc payload, run verbatim via sh (1.x transport_sh)
        assert!(script.contains("cat > /tmp/pia_openvpn_setup.sh << 'VPN_SETUP_EOF'"));
        assert!(script.contains("sh /tmp/pia_openvpn_setup.sh"));
        // credentials ride the quoted auth heredoc; the CA rides its own
        assert!(
            script.contains("cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'\np1234567\ntestpass")
        );
        assert!(script.contains("chmod 600 /etc/openvpn/pia.auth"));
        // endpoint pool + remote-random + the validated no-persist-tun
        assert!(script.contains("uci add_list openvpn.pia.remote='151.241.122.99 8080'"));
        assert!(script.contains("uci set openvpn.pia.remote_random='1'"));
        assert!(!script.contains("uci set openvpn.pia.persist_tun"));
        // kill switch + management rules + tunnel DNS
        assert!(script.contains("uci set firewall.vpn_killswitch.target='REJECT'"));
        assert!(script.contains("uci set firewall.vpn_mgmt.name='Allow-VPN-Management'"));
        assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='10.0.0.243'"));
        // the failure TAIL removes the kill switch when tun0 never comes up
        assert!(script.contains("removing kill switch to restore WAN"));

        // branches: kill switch off drops the rule AND the tail; mgmt off
        // drops the rule; empty gateway drops the route pin block
        let no_kill = render_shell(&plan_for(Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
            username: "p1234567".into(),
            password: "testpass".into(),
            kill_switch: false,
            allow_management: false,
            ..VpnPiaOpenvpnProfile::default()
        })));
        assert!(!no_kill.contains("vpn_killswitch"));
        assert!(!no_kill.contains("vpn_mgmt"));
        assert!(!no_kill.contains("ip route replace"));
        assert!(no_kill.contains("vpn_zone"));

        // gates: required creds, control chars (heredoc line injection),
        // IPv4 remotes/gateway, numeric port, iface charset
        assert!(matches!(
            VpnPiaOpenvpnProfile::default().validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        let base = VpnPiaOpenvpnProfile {
            username: "p1".into(),
            password: "pw".into(),
            ..VpnPiaOpenvpnProfile::default()
        };
        assert!(base.validate().is_ok());
        for hostile in [
            VpnPiaOpenvpnProfile {
                password: "line1\nline2".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                password: "PIA_AUTH_EOF".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                username: "VPN_SETUP_EOF".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                username: "p1\nroot".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                port: "8080; reboot".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                upstream_gateway: "not-an-ip".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                upstream_iface: "wan; poweroff".into(),
                ..base.clone()
            },
            VpnPiaOpenvpnProfile {
                remotes: vec!["$(reboot)".into()],
                ..base
            },
        ] {
            assert!(
                matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
                "gate must reject {hostile:?}"
            );
        }
    }

    #[test]
    fn nodns_payloads_substitution_and_validator_gates() {
        let script = render_shell(&plan_for(Profile::Nodns(NodnsProfile::default())));
        assert!(script.contains("cat > /etc/init.d/nodns-bridge << 'NODNS_INIT_EOF'"));
        assert!(script.contains("procd_set_param command /usr/bin/nodns-poll.sh"));
        assert!(script.contains("cat > /usr/bin/nodns-poll.sh << 'NODNS_POLL_EOF'"));
        // substituted values land inside the poll script, no placeholders leak
        assert!(script.contains("ZONE=\"nodns.shop\""));
        assert!(script.contains("API_URL=\"https://nodns.shop\""));
        assert!(script.contains("POLL_INTERVAL=300"));
        assert!(!script.contains("__ZONE__"));
        assert!(!script.contains("__URL__"));
        assert!(!script.contains("__POLL_INTERVAL__"));
        // the awk zone parser rides along verbatim
        assert!(script.contains("if (name == \"@\") name = z"));
        assert!(
            script.contains("uci add_list dhcp.@dnsmasq[0].addnhosts='/etc/dnsmasq.d/nodns.hosts'")
        );
        assert!(script.contains("uci commit dhcp"));
        assert!(script.contains("/etc/init.d/nodns-bridge enable"));
        assert!(script.contains("/etc/init.d/nodns-bridge start"));
        assert!(script.contains(
            "echo \"nodns bridge configured: zone=nodns.shop interval=300s url=https://nodns.shop\""
        ));

        let flipped = render_shell(&plan_for(Profile::Nodns(NodnsProfile {
            zone: "example.net".into(),
            api_url: "http://localhost:8080".into(),
            poll_interval: 60,
        })));
        assert!(flipped.contains("ZONE=\"example.net\""));
        assert!(flipped.contains("API_URL=\"http://localhost:8080\""));
        assert!(flipped.contains("POLL_INTERVAL=60"));

        // 1.x validators: interval range, URL scheme, zone whitespace
        assert!(matches!(
            NodnsProfile {
                poll_interval: 59,
                ..NodnsProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            NodnsProfile {
                api_url: "ftp://x".into(),
                ..NodnsProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            NodnsProfile {
                zone: "bad zone".into(),
                ..NodnsProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // shell metacharacters refuse (values interpolate into the
        // runtime script's double-quoted assignments)
        assert!(matches!(
            NodnsProfile {
                api_url: "https://x/$(reboot)".into(),
                ..NodnsProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            NodnsProfile {
                zone: "a;reboot".into(),
                ..NodnsProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn auto_sqm_script_hook_branches_and_gates() {
        let script = render_shell(&plan_for(Profile::AutoSqm(AutoSqmProfile {
            download_kbps: 20_000,
            ..AutoSqmProfile::default()
        })));
        assert!(script.contains("uci set auto_sqm.config=auto_sqm"));
        assert!(script.contains("uci set auto_sqm.config.mode='static'"));
        assert!(script.contains("uci set auto_sqm.config.download_kbps='20000'"));
        assert!(script.contains("uci commit auto_sqm"));
        assert!(script.contains("cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm"));
        // the runtime script body rides along verbatim
        assert!(script.contains("measure_wget() {"));
        assert!(script.contains("apply_sqm \"$DL_SPEED\" \"$UL_SPEED\""));
        assert!(script.contains("cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune"));
        assert!(script.contains(
            "[ \"$ACTION\" = \"ifup\" ] && [ \"$INTERFACE\" = \"wan\" ] && /usr/sbin/auto-sqm &"
        ));
        // static + known speeds: run immediately
        assert!(script.contains("/usr/sbin/auto-sqm\n"));
        assert!(!script.contains("crontabs/root"));

        // dynamic: cron entry + cron enable/restart, no immediate run
        let dynamic = render_shell(&plan_for(Profile::AutoSqm(AutoSqmProfile {
            mode: "dynamic".into(),
            dynamic_interval_hours: 6,
            ..AutoSqmProfile::default()
        })));
        assert!(dynamic.contains("sed -i '/auto-sqm/d' /etc/crontabs/root"));
        assert!(dynamic.contains("echo '0 */6 * * * /usr/sbin/auto-sqm' >> /etc/crontabs/root"));
        assert!(dynamic.contains("/etc/init.d/cron enable"));
        assert!(dynamic.contains("/etc/init.d/cron restart"));
        assert!(dynamic.contains("echo 'auto-sqm: will measure and configure on WAN ifup'"));

        // interface_name charset gates (both fields)
        assert!(matches!(
            AutoSqmProfile {
                interface: "wan; rm".into(),
                ..AutoSqmProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            AutoSqmProfile {
                device: "eth0 x".into(),
                ..AutoSqmProfile::default()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
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
    fn wireguard_profiles_ensure_kernel_module_for_runtime_applies() {
        // Runtime applies on vanilla apk/opkg-era images need the kernel
        // module — the historical package set (wireguard-tools,
        // luci-proto-wireguard) only worked because ASU bakes resolved
        // kmod dependencies at image build time (x1860 25.12.6 hardware
        // finding, lane wanapk).
        let client = plan_for(Profile::WireguardClient(WireguardClientProfile {
            peer_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
            endpoint_host: "vpn.example.com".into(),
            ..WireguardClientProfile::default()
        }));
        let server = plan_for(Profile::WireguardServer(WireguardServerProfile::default()));
        for plan in [client, server] {
            assert!(
                plan.ops.iter().any(
                    |op| matches!(op, PlanOp::EnsurePackage { name } if name == "kmod-wireguard")
                ),
                "wireguard plans must ensure kmod-wireguard for runtime applies"
            );
        }
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
