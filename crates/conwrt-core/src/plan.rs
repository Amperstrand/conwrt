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

/// Cashu VPN client — port of the 1.x `cashu-vpn-client` preset
/// (`scripts/use_cases/cashu_vpn_client.py`, experimental in 1.x): a
/// full-tunnel WireGuard client for the vps-on-demand Cashu VPN exit.
/// The operator pays the peer service out-of-band (Cashu token in the
/// `X-Cashu` header of `POST /peer`) and receives
/// `{peer_ip, public_key, endpoint, allowed_ips}` — those values are
/// pasted into this profile. Only the router side is configured here;
/// no tokens or private keys are baked into firmware (1.x contract).
///
/// Documented deviations from 1.x:
/// - `server_host` has **no default** (1.x defaulted to a since-dead
///   endpoint IP; the empty default + validator forces an explicit host).
/// - `wireguard-kmod` (not a real OpenWrt package name) is corrected to
///   `kmod-wireguard`, matching the wireguard-client port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashuVpnClientProfile {
    /// WireGuard private key, or `generate` (1.x default) to
    /// auto-generate per device on first boot.
    pub private_key: String,
    /// VPN exit public key (from `POST /peer` `public_key`).
    pub peer_public_key: String,
    /// Tunnel IP assigned by the VPN exit, with CIDR (from `POST /peer`
    /// `peer_ip`) — lands on the interface's `addresses`.
    pub peer_ip: String,
    /// VPN exit hostname or IPv4 (from `POST /peer` `endpoint`).
    pub server_host: String,
    /// VPN exit UDP port (1.x default 51820).
    pub server_port: u16,
    /// IPs routed through the tunnel (1.x default `0.0.0.0/0` = full
    /// v4 tunnel).
    pub allowed_ips: String,
    /// Comma-separated DNS servers through the tunnel (1.x default
    /// `1.1.1.1`; empty = use the peer's).
    pub dns: String,
    /// Fail closed: reject LAN→WAN forwarding unless the tunnel
    /// handshakes (1.x default on). The post-apply guard removes the
    /// rule when no handshake appears within 30 s (fail-open, 1.x).
    pub kill_switch: bool,
}

impl Default for CashuVpnClientProfile {
    fn default() -> Self {
        Self {
            private_key: "generate".into(),
            peer_public_key: String::new(),
            peer_ip: String::new(),
            server_host: String::new(),
            server_port: 51820,
            allowed_ips: "0.0.0.0/0".into(),
            dns: "1.1.1.1".into(),
            kill_switch: true,
        }
    }
}

impl CashuVpnClientProfile {
    /// 1.x required-param gates (`peer_public_key`, `peer_ip`) plus the
    /// `shell_safe::validate_host`/`validate_port` parity used by the
    /// sibling wireguard-client port.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.peer_public_key.is_empty() {
            return Err(Unsupported::InvalidParams(
                "peer_public_key is required (VPN exit public key from POST /peer)".into(),
            ));
        }
        if self.peer_ip.is_empty() || !self.peer_ip.contains('/') {
            return Err(Unsupported::InvalidParams(
                "peer_ip is required with a CIDR (e.g. `10.66.42.2/32`, from POST /peer)".into(),
            ));
        }
        // The status line interpolates peer_ip into a single-quoted shell
        // string — a quote-bearing value passed the old contains('/')
        // gate (Codex P1, #524): gate the CIDR charset outright.
        if !self
            .peer_ip
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/'))
        {
            return Err(Unsupported::InvalidParams(
                "peer_ip must be a CIDR address (hex digits, ':', '.', '/' only)".into(),
            ));
        }
        if !valid_host(&self.server_host) {
            return Err(Unsupported::InvalidParams(
                "server_host must be a valid hostname or IPv4 address".into(),
            ));
        }
        if self.server_port == 0 {
            return Err(Unsupported::InvalidParams(
                "server_port must be 1-65535".into(),
            ));
        }
        if self.allowed_ips.is_empty() {
            return Err(Unsupported::InvalidParams(
                "allowed_ips must be a non-empty comma-separated CIDR list".into(),
            ));
        }
        Ok(())
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

/// MPTCP connection bonding via BondingShouldBeFree — port of the
/// tested 1.x `mptcp-bonding` preset (`scripts/use_cases/
/// mptcp_bonding.py`, verified on SNAPSHOT r35226 / kernel 6.18). True
/// per-connection aggregation: xray-core (VLESS) on a VPS deaggregates
/// MPTCP subflows from up to 8 WANs — mwan3 routes connections, BSBF
/// splits ONE connection across all of them. Like rescue-watchdog
/// there is no static UCI to shape: the surface is ONE remote
/// installer line (`curl owrt.bondingshouldbefree.org | sh -s -- …`)
/// plus verify hints. An MPTCP kernel (OpenWrt 25.12+/SNAPSHOT) is a
/// device prerequisite the plan cannot ensure — 24.10 (CONFIG_MPTCP=n)
/// must be excluded upstream; the 1.x closing comments say the same.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MptcpBondingProfile {
    /// VPS running the BSBF server — IPv4 or hostname (1.x required
    /// param, `shell_safe::validate_host` parity).
    pub server_ipv4: String,
    /// Client port issued by `bsbf-add-client` on the VPS (1.x required
    /// param, `validate_port` parity).
    pub server_port: u16,
    /// Client UUID issued by `bsbf-add-client` (1.x required param).
    pub uuid: String,
}

impl MptcpBondingProfile {
    /// 1.x gated only non-emptiness, then interpolated all three values
    /// UNQUOTED into a `curl | sh -s --` line — `;`/`$()`/backticks in
    /// any param meant remote shell injection. The port mirrors the
    /// Python-side fix that landed with it (validate_host / numeric
    /// port / uuid token charset); valid input renders byte-identically.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if !valid_host(&self.server_ipv4) {
            return Err(Unsupported::InvalidParams(
                "server_ipv4 must be a valid hostname or IPv4 address".into(),
            ));
        }
        if self.server_port == 0 {
            return Err(Unsupported::InvalidParams(
                "server_port must be 1-65535".into(),
            ));
        }
        if self.uuid.is_empty()
            || !self
                .uuid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(Unsupported::InvalidParams(
                "uuid contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// OpenTollGate — Bitcoin/Lightning payment gateway for selling
/// internet access — port of the tested 1.x `tollgate` preset
/// (`scripts/use_cases/tollgate.py`, ops characterization + transport
/// parity + physical router verification). FLASH-TIME slice: the plan
/// shapes the nodogsplash captive portal (branding, users_to_router
/// allow rules), installs the WiFi-STA hotplug hook, stages the
/// payment config (named section — the 1.x anonymous `uci add`
/// accumulated a new section per re-run, fixed Python-side with this
/// port), and optionally patches byte pricing into the ipk's
/// config.json. The tollgate ipk itself is a POST-FLASH, host-side
/// step (`deploy_tollgate_post_flash`: nostr/GitHub-CI resolve → SCP
/// → opkg/apk) — 1.x marks the preset post-flash for exactly that.
/// IVPN WireGuard VPN — port of the 1.x `vpn-ivpn` preset
/// (`scripts/use_cases/vpn_providers/ivpn.py`, 1.x marks it UNTESTED).
/// Runtime-API twin of the pia/surfshark family: one transport-heredoc
/// script registers a WG key with the IVPN API (account-id auth),
/// picks the first public-key-bearing server, configures wg0 + the
/// endpoint /32 route; the shared firewall/DNS/verify composition
/// follows. The 1.x script carried the whole #604 defect class —
/// literal `${WG_PUB}` in single-quoted JSON (registration NEVER
/// worked), no abort guards before the destructive wg0 cleanup, no
/// address readback, no revert baseline — all fixed Python-side with
/// this port; `validate()` gates the baked-in values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnIvpnProfile {
    /// IVPN account ID (e.g. `ivpn-xxxxx`); charset-gated — it rides
    /// the API URL query inside the script text.
    pub account_id: String,
    /// Upstream gateway IP pinning the endpoint /32 route.
    pub upstream_gateway: String,
    /// Upstream interface for the route (1.x default `wwan`).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops (paired with the
    /// shared fail-open verify tail).
    pub kill_switch: bool,
}

impl Default for VpnIvpnProfile {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            upstream_gateway: String::new(),
            upstream_iface: "wwan".into(),
            kill_switch: true,
        }
    }
}

impl VpnIvpnProfile {
    /// Charset gates mirroring the Python-side `_resolve_params` fix:
    /// the account id rides the URL query, the gateway a quoted uci
    /// value, the iface both.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let account_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        if !account_ok(&self.account_id) {
            return Err(Unsupported::InvalidParams(
                "account_id must be letters/digits/underscores/hyphens".into(),
            ));
        }
        if self.upstream_gateway.is_empty()
            || !self
                .upstream_gateway
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
        {
            return Err(Unsupported::InvalidParams(
                "upstream_gateway must be an IPv4 address".into(),
            ));
        }
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.upstream_iface) {
            return Err(Unsupported::InvalidParams(
                "upstream_iface contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// Mullvad WireGuard VPN — port of the 1.x `vpn-mullvad` preset
/// (`scripts/use_cases/vpn_providers/mullvad.py`, 1.x marks it
/// UNTESTED). Runtime-API twin: token-authenticated WG peer
/// registration, optional 2-letter country server select, the shared
/// composition after. Carried the same #604 defect class as ivpn —
/// fixed Python-side with this port; gates below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnMullvadProfile {
    /// Mullvad account token (Authorization: Token header); charset-
    /// gated — it rides the header inside the script text.
    pub account_token: String,
    /// 2-letter country code filter (empty = first server).
    pub country: String,
    /// Upstream gateway IP pinning the endpoint /32 route.
    pub upstream_gateway: String,
    /// Upstream interface for the route (1.x default `wwan`).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops.
    pub kill_switch: bool,
}

impl Default for VpnMullvadProfile {
    fn default() -> Self {
        Self {
            account_token: String::new(),
            country: String::new(),
            upstream_gateway: String::new(),
            upstream_iface: "wwan".into(),
            kill_switch: true,
        }
    }
}

impl VpnMullvadProfile {
    /// Charset gates mirroring the Python-side fix (token in the
    /// Authorization header, 2-letter country in the jq select,
    /// dotted-quad gateway, interface charset).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let token_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        if !token_ok(&self.account_token) {
            return Err(Unsupported::InvalidParams(
                "account_token must be letters/digits/dots/hyphens".into(),
            ));
        }
        if !self.country.chars().all(|c| c.is_ascii_alphabetic()) || self.country.len() > 2 {
            return Err(Unsupported::InvalidParams(
                "country must be a 2-letter code".into(),
            ));
        }
        if self.upstream_gateway.is_empty()
            || !self
                .upstream_gateway
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
        {
            return Err(Unsupported::InvalidParams(
                "upstream_gateway must be an IPv4 address".into(),
            ));
        }
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.upstream_iface) {
            return Err(Unsupported::InvalidParams(
                "upstream_iface contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// Self-announcing WireGuard VPN server — port of the 1.x `vpn-node`
/// preset (`scripts/use_cases/vpn_node.py`, 1.x marks it untested).
/// Not a tunnel configurer: the plan installs the Nostr Europa
/// listing publisher (a first-boot script that signs a kind-30402
/// event with `nak` using the operator's nsec, read from a 600-perm
/// file at run time — the secret never rides the script's command
/// line in cleartext logs beyond the initial write). The WireGuard
/// SERVER half is the separate `wireguard-server` preset — the 1.x
/// docstring pairs them. Everything is baked into the script text at
/// build time, so `validate()` gates every value (the surfshark #604
/// class, plus a 1.x non-determinism fix: the d_tag fallback was a
/// TIMESTAMP contradicting the declared `vpn-node` default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNodeProfile {
    /// Operator Nostr nsec (hex or `nsec1…` bech32) — lands inside a
    /// single-quoted `echo` writing the 600-perm secret file.
    pub nsec: String,
    /// Nostr listing d-tag identifier (1.x default `vpn-node`).
    pub d_tag: String,
    /// Listing title (single-quoted shell arg AND JSON string).
    pub title: String,
    /// Public hostname or IP clients connect to (JSON endpoint).
    pub endpoint_host: String,
    /// WireGuard UDP port for the JSON endpoint.
    pub endpoint_port: u16,
    /// ISO country code for the region tag.
    pub country: String,
    /// Price in sats.
    pub price_amount: u32,
    /// Price unit: hour, day, week, month.
    pub price_unit: String,
    /// Listing description (same quoting surface as title).
    pub content: String,
    /// Comma-separated wss:// relay URLs — BARE shell words in the
    /// script, so the URL charset is the safety story.
    pub relays: String,
    /// Path to the nak binary (default `/usr/bin/nak`).
    pub nak_path: String,
}

impl Default for VpnNodeProfile {
    fn default() -> Self {
        Self {
            nsec: String::new(),
            d_tag: "vpn-node".into(),
            title: "VPN Node".into(),
            endpoint_host: String::new(),
            endpoint_port: 51820,
            country: "US".into(),
            price_amount: 50,
            price_unit: "hour".into(),
            content: "VPN node. WireGuard. No logs.".into(),
            relays: "wss://relay.damus.io,wss://relay.cashu.email".into(),
            nak_path: "/usr/bin/nak".into(),
        }
    }
}

impl VpnNodeProfile {
    /// Charset gates mirroring the Python-side `_resolve_params` fix:
    /// every value is baked into the transport-script text (single-
    /// and double-quoted args, a JSON string, bare shell words).
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.nsec.is_empty() || !self.nsec.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Unsupported::InvalidParams(
                "nsec must be hex (or nsec1… bech32) — no quotes or metacharacters".into(),
            ));
        }
        if self.d_tag.is_empty()
            || !self
                .d_tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(Unsupported::InvalidParams(
                "d_tag must be letters/digits/dots/hyphens".into(),
            ));
        }
        let text_ok = |v: &str| {
            !v.is_empty() && !v.contains(['\'', '"', '\\']) && !v.chars().any(|c| (c as u32) < 0x20)
        };
        for (field, value) in [("title", &self.title), ("content", &self.content)] {
            if !text_ok(value) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must not contain quotes, backslashes, or control characters"
                )));
            }
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
        if self.country.len() != 2 || !self.country.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(Unsupported::InvalidParams(
                "country must be a 2-letter code".into(),
            ));
        }
        if self.price_amount == 0 {
            return Err(Unsupported::InvalidParams(
                "price_amount must be a positive integer (sats)".into(),
            ));
        }
        if !matches!(self.price_unit.as_str(), "hour" | "day" | "week" | "month") {
            return Err(Unsupported::InvalidParams(
                "price_unit must be one of: hour, day, week, month".into(),
            ));
        }
        for relay in self.relays.split(',') {
            let ok = relay.starts_with("wss://")
                && relay.len() > 6
                && relay["wss://".len()..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | ':' | '_'));
            if !ok {
                return Err(Unsupported::InvalidParams(format!(
                    "relay {relay:?} must be a wss:// URL without quotes/spaces/metacharacters"
                )));
            }
        }
        if self.nak_path.is_empty()
            || !self.nak_path.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '(' | ')' | '-')
            })
        {
            return Err(Unsupported::InvalidParams(
                "nak_path contains unsafe characters".into(),
            ));
        }
        Ok(())
    }

    /// The Europa listing JSON, byte-identical to the 1.x f-string.
    fn listing_json(&self) -> String {
        format!(
            "{{\"type\":\"vpn-service\",\"name\":\"{title}\",\
             \"endpoint\":\"{host}:{port}\",\
             \"protocols\":[\"wireguard\"],\
             \"prices\":[{{\"amount\":{amount},\"currency\":\"sat\",\"unit\":\"{unit}\"}}],\
             \"policies\":[\"no-logs\"],\
             \"content\":\"{content}\"}}",
            title = self.title,
            host = self.endpoint_host,
            port = self.endpoint_port,
            amount = self.price_amount,
            unit = self.price_unit,
            content = self.content,
        )
    }
}

/// NordVPN IKEv2/IPsec via strongSwan — port of the 1.x
/// `vpn-nordvpn-ikev2` preset (`scripts/use_cases/vpn_providers/
/// nordvpn.py`). EAP-MSCHAPv2 auth against NordVPN's IPsec gateways
/// with kernel ESP. Hardware-bring-up lessons baked in (2026-10-08,
/// COVR-X1860 / MT7621): socket-default is mandatory, eap-identity
/// answers the EAP_IDENTITY request, ESP proposals must NOT include
/// modp, and the stock mt7621 kernel ships without XFRM (the
/// kmod-ipsec* packages are in the plan).
///
/// Purity contract (the vpn-nordvpn WireGuard precedent): 1.x resolves
/// EAP credentials + server from the access token at BUILD time via
/// the NordVPN API — the I/O-free 2.x planner carries the RESOLVED
/// statics (username/password/station/hostname) and never calls the
/// API. The Python builder gained a statics-direct mode with this
/// port; `validate()` gates every value (credentials land inside
/// double-quoted swanctl values where a `"` breaks config parsing).
///
/// hw_accel: `true` = modprobe the EIP-93 crypto engine; `false` =
/// rmmod + blacklist before any SA exists (with live references it
/// wedges the kernel — AGENTS.md; SAD EINVAL was observed on kernel
/// 6.12.94 with eip93 loaded; hw_accel=false is the supported path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNordvpnIke2Profile {
    /// EAP service username (resolved from the access token at build
    /// time on the host; lands inside `eap_id = "…"`.
    pub username: String,
    /// EAP service password (lands inside `secret = "…"`).
    pub password: String,
    /// Server IPv4 (swanctl `remote_addrs`).
    pub station: String,
    /// Server hostname (display only — the echo line).
    pub hostname: String,
    /// EIP-93 hardware crypto on (false = rmmod + blacklist).
    pub hw_accel: bool,
    /// Block LAN→WAN traffic if the tunnel drops (1.x default on).
    pub kill_switch: bool,
    /// Allow SSH/LuCI to the router from the VPN zone (1.x default on).
    pub allow_management: bool,
}

impl Default for VpnNordvpnIke2Profile {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            station: String::new(),
            hostname: String::new(),
            hw_accel: true,
            kill_switch: true,
            allow_management: true,
        }
    }
}

impl VpnNordvpnIke2Profile {
    /// Gates mirroring the Python-side `_resolve_params` fix: the
    /// credentials land inside double-quoted swanctl values (a `"`
    /// or control char breaks config parsing inside the quoted
    /// heredoc — the heredoc guards shell, not swanctl syntax), the
    /// station is a bare dotted-quad `remote_addrs`, the hostname
    /// rides a double-quoted echo.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let secret_ok =
            |v: &str| !v.is_empty() && !v.contains('"') && !v.chars().any(|c| (c as u32) < 0x20);
        for (field, value) in [("username", &self.username), ("password", &self.password)] {
            if !secret_ok(value) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must not contain double quotes or control characters"
                )));
            }
        }
        if self.station.is_empty() || !self.station.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Err(Unsupported::InvalidParams(
                "station must be an IPv4 address".into(),
            ));
        }
        if self.hostname.is_empty()
            || !self
                .hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(Unsupported::InvalidParams(
                "hostname must be a plain hostname".into(),
            ));
        }
        Ok(())
    }
}

/// Surfshark WireGuard VPN — port of the 1.x `vpn-surfshark` preset
/// (`scripts/use_cases/vpn_providers/surfshark.py`, 1.x marks it
/// UNTESTED). Runtime-API twin of vpn-pia: one transport-heredoc
/// script authenticates with service credentials, registers a WG
/// keypair, auto-selects a server (optional country filter), and
/// configures wg0 + the endpoint /32 route; the shared firewall/DNS/
/// verify composition follows. Credentials, country, and gateway are
/// BAKED into the script text — validate() gates them to charsets
/// that cannot break the single-quoted JSON body, the jq test
/// pattern, or the quoted uci values (injection fix landed with this
/// port, both sides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnSurfsharkProfile {
    /// Surfshark service username (dashboard > Manual setup).
    pub username: String,
    /// Surfshark service password.
    pub password: String,
    /// Country filter for server selection (empty = first server).
    pub country: String,
    /// Upstream gateway IP pinning the endpoint /32 route.
    pub upstream_gateway: String,
    /// Upstream interface for the route (1.x default `wwan`).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops (1.x default on;
    /// paired with the shared fail-open verify tail).
    pub kill_switch: bool,
}

impl Default for VpnSurfsharkProfile {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            country: String::new(),
            upstream_gateway: String::new(),
            upstream_iface: "wwan".into(),
            kill_switch: true,
        }
    }
}

impl VpnSurfsharkProfile {
    /// Charset gates mirroring the Python-side `_resolve_params` fix:
    /// a `'` closes the script's single-quoted JSON arg, `\` breaks
    /// the JSON, quotes/semicolons inject into the jq test pattern,
    /// and the gateway/iface land in quoted uci values.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let cred_ok = |v: &str| {
            !v.is_empty()
                && !v.contains('\'')
                && !v.contains('"')
                && !v.contains('\\')
                && !v.chars().any(|c| (c as u32) < 0x20)
        };
        if !cred_ok(&self.username) {
            return Err(Unsupported::InvalidParams(
                "username must not contain quotes, backslashes, or control characters".into(),
            ));
        }
        if !cred_ok(&self.password) {
            return Err(Unsupported::InvalidParams(
                "password must not contain quotes, backslashes, or control characters".into(),
            ));
        }
        if !self
            .country
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-'))
        {
            return Err(Unsupported::InvalidParams(
                "country must be letters/digits/spaces/hyphens".into(),
            ));
        }
        if self.upstream_gateway.is_empty()
            || !self
                .upstream_gateway
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
        {
            return Err(Unsupported::InvalidParams(
                "upstream_gateway must be an IPv4 address".into(),
            ));
        }
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.upstream_iface) {
            return Err(Unsupported::InvalidParams(
                "upstream_iface contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// The surfshark runtime-API script body AFTER the shared JSON helper
/// (1.x `surfshark_script` minus `JSON_HELPER_SH`), byte-verbatim with
/// sentinel tokens for the gated interpolations.
/// The wg0 interface + peer stanza (1.x wg0_uci_sh output, verbatim)
/// shared by the runtime-API VPN presets — variables stay shell-side
/// (quoted fragments like `"$IVPN_PRIV"` are per-provider names).
const WG_STANZA_SH: &str = concat!(
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"__WG_PRIV__\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
);

/// The endpoint /32 static-route block with sentinels — each preset
/// substitutes its section name into the marker BEFORE token splice
/// (route sections are named per-provider in 1.x).
fn route_block(section: &str) -> String {
    format!(
        "# Static route: prevent circular routing through VPN tunnel\n\
         uci -q delete network.{section}\n\
         uci set network.{section}=route\n\
         uci set network.{section}.interface='__IFACE__'\n\
         uci set network.{section}.target=\"${{SERVER_IP}}\"\n\
         uci set network.{section}.netmask='255.255.255.255'\n\
         uci set network.{section}.gateway='__GATEWAY__'\n"
    )
}

/// The pre-commit address readback tail (AGENTS.md).
fn readback_block(provider: &str) -> String {
    let mut lines: Vec<String> = vec![
        "# Pre-commit IP readback (AGENTS.md): refuse to reach commit with a".into(),
        "# tunnel address that is not a sane /32 (the surfshark #604-P1 class)".into(),
        "WG_ADDR=$(uci -q get network.wg0.addresses)".into(),
        "case \"$WG_ADDR\" in".into(),
        "    */32) ;;".into(),
        "esac".into(),
    ];
    lines.insert(
        5,
        format!(
            "    *) echo \"{provider}: wg0 address '$WG_ADDR' not a sane /32 — \
             aborting before commit\"; exit 1 ;;"
        ),
    );
    lines.join("\n")
}

/// The IVPN runtime-API script body AFTER the shared JSON helper —
/// byte-verbatim vs the FIXED 1.x builder, sentinel tokens for the
/// gated interpolations.
const IVPN_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG public key with IVPN API\n",
    "KEY_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.ivpn.net/v4/account/wireguard/key?account_id=__ACCOUNT__\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$KEY_RESP\" | json_get ip_address)\n",
    "# Strip CIDR if present\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick first (.json variant — the extensionless path 404s)\n",
    "SERVERS=$(curl -s -m 15 \"https://api.ivpn.net/v4/servers.json\")\n",
    "SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.wireguard[].hosts[] | select(has(\"public_key\"))] | .[0]')\n",
    "SERVER_IP=$(echo \"$SERVER_ENTRY\" | json_get host)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get public_key)\n",
    "SERVER_PORT=$(echo \"$SERVER_ENTRY\" | json_get wg_port)\n",
    "[ -z \"$SERVER_PORT\" ] && SERVER_PORT=51820\n",
    "\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is complete\n",
    "# (the surfshark #604-P2 class: a failed key registration leaves PEER_IP\n",
    "# empty — without this guard the script below deletes a working tunnel)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] \\\n",
    "    || { echo 'IVPN: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "if [ -z \"$PEER_IP\" ]; then echo 'IVPN: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "IVPN_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
);

/// The Mullvad runtime-API script body AFTER the shared JSON helper.
const MULLVAD_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG public key with Mullvad API\n",
    "RESPONSE=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.mullvad.net/www/accounts/me/wg-peers/\" \\\n",
    "    -H \"Authorization: Token __TOKEN__\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$RESPONSE\" | json_get ipv4_address)\n",
    "# Strip CIDR if present (Mullvad returns 10.xx.xx.xx/32)\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick best server\n",
    "SERVERS=$(curl -s -m 15 -H \"Accept: application/json\" \"https://api.mullvad.net/www/relays/wireguard/\")\n",
    "if [ -n \"__COUNTRY_FILTER__\" ]; then\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.[] | select(.country_code==\"__COUNTRY__\")] | .[0]')\n",
    "else\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '.[0]')\n",
    "fi\n",
    "SERVER_IP=$(echo \"$SERVER_ENTRY\" | json_get ipv4_addr_in)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get pubkey)\n",
    "SERVER_HOST=$(echo \"$SERVER_ENTRY\" | json_get hostname)\n",
    "SERVER_PORT=51820\n",
    "\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is\n",
    "# complete (surfshark #604-P2 class)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] \\\n",
    "    || { echo 'Mullvad: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "if [ -z \"$PEER_IP\" ]; then echo 'Mullvad: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "MULLVAD_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
);

const SURFSHARK_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Authenticate with Surfshark — get auth token\n",
    "AUTH_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.surfshark.com/v1/auth/login\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"username\":\"__USERNAME__\",\"password\":\"__PASSWORD__\"}')\n",
    "AUTH_TOKEN=$(echo \"$AUTH_RESP\" | json_get token)\n",
    "\n",
    "# Generate WireGuard configuration\n",
    "WG_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.surfshark.com/v1/account/wireguard/new\" \\\n",
    "    -H \"Authorization: Bearer ${AUTH_TOKEN}\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"publicKey\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$WG_RESP\" | json_get ipAddress)\n",
    "# Strip CIDR if present\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick best (v4 clusters: public endpoint, hostname-only\n",
    "# entries — connectionName/pubKey; no IP field, so the endpoint is a DNS name)\n",
    "SERVERS=$(curl -s -m 15 \\\n",
    "    \"https://api.surfshark.com/v4/server/clusters/generic?countryCode=\" \\\n",
    "    -H \"Content-Type: application/json\")\n",
    "if [ -n \"__COUNTRY_FILTER__\" ]; then\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.[] | select(.country | test(\"__COUNTRY__\";\"i\"))] | .[0]')\n",
    "else\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '.[0]')\n",
    "fi\n",
    "SERVER_HOST=$(echo \"$SERVER_ENTRY\" | json_get connectionName)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get pubKey)\n",
    "SERVER_PORT=51820\n",
    "# Resolve the endpoint hostname for the static /32 route; skip the route\n",
    "# (netifd's wireguard proto installs its own endpoint route) when DNS fails.\n",
    "# BusyBox nslookup (OpenWrt 25.12.5, verified live 2026-10-14) prints the\n",
    "# resolver as \"Address: <ip>:53\" and each answer as \"Address: <ip>\".\n",
    "SERVER_IP=$(nslookup \"$SERVER_HOST\" 2>/dev/null | awk '$1==\"Address:\" && $2 ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/ {print $2}' | tail -1)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_HOST\" ] \\\n",
    "    || { echo 'Surfshark: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    // a failed key registration (error JSON) leaves PEER_IP empty —
    // without this guard the script below would DELETE the working
    // wg0 and write addresses=/32 (Codex #604 P2 round 2)
    "if [ -z \"$PEER_IP\" ]; then echo 'Surfshark: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "SS_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
    "# Configure WireGuard interface\n",
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"$SS_PRIV\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_HOST\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
    "\n",
    "\n",
    "if [ -n \"$SERVER_IP\" ]; then\n",
    "# Static route: prevent circular routing through VPN tunnel\n",
    "uci -q delete network.surfshark_server_route\n",
    "uci set network.surfshark_server_route=route\n",
    "uci set network.surfshark_server_route.interface='__IFACE__'\n",
    "uci set network.surfshark_server_route.target=\"${SERVER_IP}\"\n",
    "uci set network.surfshark_server_route.netmask='255.255.255.255'\n",
    "uci set network.surfshark_server_route.gateway='__GATEWAY__'\n",
    "else\n",
    "    echo \"Surfshark: endpoint DNS unresolved — skipping static route (netifd installs its own)\"\n",
    "fi\n",
    "\n",
    "# Pre-commit IP readback (AGENTS.md): the shared ops below commit\n",
    "# and restart networking — refuse to reach commit with a tunnel\n",
    "# address that is not a sane /32 (Codex #604 P1 round 3).\n",
    "WG_ADDR=$(uci -q get network.wg0.addresses)\n",
    "case \"$WG_ADDR\" in\n",
    "    */32) ;;\n",
    "    *) echo \"Surfshark: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit\"; exit 1 ;;\n",
    "esac\n",
);

/// Single left-to-right pass over `__TOKEN__` placeholders: inserted
/// values are never re-scanned, so a credential that itself contains
/// token-shaped text (`abc__IFACE__def`) survives verbatim — chained
/// `.replace()` calls would rewrite it (Codex #604 P2 round 5).
fn substitute_tokens(template: &str, pairs: &[(&str, &str)]) -> String {
    // generic single-pass: at each step splice the EARLIEST token
    // occurrence and continue after the inserted value — inserted
    // values are never re-scanned, whatever their shape (token styles
    // vary: `__TOK__`, `{iface}` …). Non-token text passes through.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let mut best: Option<(usize, &str, &str)> = None;
        for (tok, val) in pairs {
            if let Some(pos) = rest.find(tok) {
                if best.is_none_or(|(p, _, _)| pos < p) {
                    best = Some((pos, tok, val));
                }
            }
        }
        match best {
            Some((pos, tok, val)) => {
                out.push_str(&rest[..pos]);
                out.push_str(val);
                rest = &rest[pos + tok.len()..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

/// Shared tail assembly for the runtime-API VPN presets: wg0 stanza
/// (per-provider shell var name), per-provider static-route section,
/// and the pre-commit address readback — spliced with the planner's
/// tokens in ONE substitution pass.
/// The vpn-node first-boot publisher script, byte-verbatim vs the
/// FIXED 1.x builder — sentinel tokens for the gated interpolations
/// (nak path, d_tag, region, price, listing JSON, relays, nsec).
/// NOTE: unlike the runtime-API VPN presets there is no transport
/// heredoc wrapper — the 1.x op IS this script directly.
const VPN_NODE_FIRST_BOOT_SH: &str = concat!(
    "cat > /etc/vpn-listing.sh << 'SCRIPT'\n",
    "#!/bin/sh\n",
    "# Publish Europa listing on first boot\n",
    "NSEC_FILE=\"/etc/vpn-node/nsec\"\n",
    "WG_PUBKEY=$(wg show wg0 public-key 2>/dev/null)\n",
    "if [ -z \"$WG_PUBKEY\" ] || [ ! -f \"$NSEC_FILE\" ]; then\n",
    "    echo \"vpn-listing: missing wg0 pubkey or nsec, skipping\" >&2\n",
    "    exit 0\n",
    "fi\n",
    "NSEC=$(cat \"$NSEC_FILE\")\n",
    "__NAK__ event \\\n",
    "    -k 30402 \\\n",
    "    --sec \"$NSEC\" \\\n",
    "    -d \"__DTAG__\" \\\n",
    "    -t \"t=vpn-service\" \\\n",
    "    -t \"t=wireguard\" \\\n",
    "    -t \"protocol=wireguard\" \\\n",
    "    -t \"region=__COUNTRY__\" \\\n",
    "    -t \"price=__PRICE__\" \\\n",
    "    -c '__LISTING_JSON__' \\\n",
    "    __RELAYS__ 2>&1\n",
    "echo \"vpn-listing: published\"\n",
    "SCRIPT\n",
    "chmod +x /etc/vpn-listing.sh\n",
    "\n",
    "mkdir -p /etc/vpn-node\n",
    "echo '__NSEC__' > /etc/vpn-node/nsec\n",
    "chmod 600 /etc/vpn-node/nsec\n",
    "\n",
    "( sleep 30 && /etc/vpn-listing.sh > /tmp/vpn-listing.log 2>&1 ) &\n",
);

fn plan_vpn_node(model: &DeviceModel, vn: &VpnNodeProfile) -> Result<Plan, Unsupported> {
    vn.validate()?;
    // single-pass: the nsec/relays/listing JSON are values, never
    // re-scanned (token-shaped payloads survive verbatim)
    let body = substitute_tokens(
        VPN_NODE_FIRST_BOOT_SH,
        &[
            ("__NAK__", vn.nak_path.as_str()),
            ("__DTAG__", vn.d_tag.as_str()),
            ("__COUNTRY__", vn.country.as_str()),
            (
                "__PRICE__",
                format!("{}sat/{}", vn.price_amount, vn.price_unit).as_str(),
            ),
            ("__LISTING_JSON__", vn.listing_json().as_str()),
            (
                "__RELAYS__",
                vn.relays.split(',').collect::<Vec<_>>().join(" ").as_str(),
            ),
            ("__NSEC__", vn.nsec.as_str()),
        ],
    );
    let mut ops: Vec<PlanOp> = ["wireguard-tools", "luci-proto-wireguard"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell { command: body });
    let verification = vec![
        VerificationCheck {
            description: "listing publisher installed and executable".into(),
            command: "test -x /etc/vpn-listing.sh && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "operator nsec file written".into(),
            command: "test -f /etc/vpn-node/nsec && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-node".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

const NORDVPN_IKE2_CA_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ\n",
    "MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2\n",
    "MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV\n",
    "BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI\n",
    "hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF\n",
    "kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr\n",
    "XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU\n",
    "eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV\n",
    "skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu\n",
    "MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA\n",
    "37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR\n",
    "hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s\n",
    "Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy\n",
    "WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6\n",
    "MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST\n",
    "LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG\n",
    "SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g\n",
    "nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/\n",
    "k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S\n",
    "DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/\n",
    "pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo\n",
    "k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp\n",
    "+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd\n",
    "NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa\n",
    "wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC\n",
    "VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S\n",
    "PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==\n",
    "-----END CERTIFICATE-----\n",
);

/// The IKEv2 swanctl connection config (byte-verbatim vs 1.x, with
/// sentinel tokens for the gated interpolations). Written to
/// /etc/swanctl/conf.d/nordvpn-ikev2.conf inside a quoted heredoc.
const NORDVPN_IKE2_SWANCTL_SH: &str = concat!(
    "connections {\n",
    "  nordvpn {\n",
    "    version = 2\n",
    "    send_cert = never\n",
    "    local_addrs = %defaultroute\n",
    "    remote_addrs = __STATION__\n",
    "    proposals = aes256-sha256-modp2048, aes256-sha1-modp2048, aes128-sha256-modp2048\n",
    "    reauth_time = 0s\n",
    "    fragmentation = yes\n",
    "    mobike = yes\n",
    "    local {\n",
    "      auth = eap\n",
    "      eap_id = \"__USERNAME__\"\n",
    "    }\n",
    "    remote {\n",
    "      auth = pubkey\n",
    "      id = %any\n",
    "    }\n",
    "    vips = 0.0.0.0\n",
    "    dpd_delay = 60s\n",
    "    children {\n",
    "      nord {\n",
    "        remote_ts = 0.0.0.0/0\n",
    "        local_ts = dynamic\n",
    "        start_action = start\n",
    "        close_action = restart\n",
    "        esp_proposals = aes256-sha256, aes256-sha1, aes128-sha256\n",
    "        rekey_time = 3600s\n",
    "      }\n",
    "    }\n",
    "  }\n",
    "}\n",
    "secrets {\n",
    "  eap-nord {\n",
    "    secret = \"__PASSWORD__\"\n",
    "  }\n",
    "}",
);

fn plan_vpn_nordvpn_ike2(
    model: &DeviceModel,
    i2: &VpnNordvpnIke2Profile,
) -> Result<Plan, Unsupported> {
    i2.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = [
        "strongswan",
        "strongswan-charon",
        "strongswan-swanctl",
        "strongswan-mod-aes",
        "strongswan-mod-sha1",
        "strongswan-mod-sha2",
        "strongswan-mod-gmp",
        "strongswan-mod-hmac",
        "strongswan-mod-pubkey",
        "strongswan-mod-x509",
        "strongswan-mod-pem",
        "strongswan-mod-random",
        "strongswan-mod-nonce",
        "strongswan-mod-eap-identity",
        "strongswan-mod-eap-mschapv2",
        "strongswan-mod-md4",
        "strongswan-mod-kernel-netlink",
        "strongswan-mod-updown",
        "strongswan-mod-attr",
        "strongswan-mod-openssl",
        "strongswan-mod-socket-default",
        "kmod-ipsec4",
        "kmod-xfrm-interface",
        "kmod-nft-xfrm",
    ]
    .iter()
    .map(|name| PlanOp::EnsurePackage {
        name: (*name).into(),
    })
    .collect();
    // hw_accel branch: true = modprobe the EIP-93; false = rmmod +
    // blacklist before any SA exists (with live references it wedges
    // the kernel — AGENTS.md; the 1.x hardware lessons)
    let hw_block = if i2.hw_accel {
        "modprobe crypto_hw_eip93 2>/dev/null || true\n".to_string()
    } else {
        concat!(
            "rmmod crypto_hw_eip93 2>/dev/null || true\n",
            "mkdir -p /etc/modprobe.d\n",
            "echo 'blacklist crypto_hw_eip93' > /etc/modprobe.d/no-eip93.conf\n",
        )
        .to_string()
    };
    let hw_echo = if i2.hw_accel { "on" } else { "off" };
    let swanctl = substitute_tokens(
        NORDVPN_IKE2_SWANCTL_SH,
        &[
            ("__STATION__", i2.station.as_str()),
            ("__USERNAME__", i2.username.as_str()),
            ("__PASSWORD__", i2.password.as_str()),
        ],
    );
    let bringup = "( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &\n\
                   ( sleep 20; swanctl --load-all >/dev/null 2>&1; \
                    swanctl --initiate --child nord >/dev/null 2>&1; ) &";
    // transport script body, line-by-line for byte fidelity with the
    // FIXED 1.x builder (golden: tests/goldens/vpn-nordvpn-ikev2.sh)
    let mut body = String::new();
    body.push_str("# --- NordVPN IKEv2 (strongSwan, EAP-MSCHAPv2) ---\n");
    body.push_str(&hw_block);
    body.push('\n');
    body.push_str("mkdir -p /var/ipsec /etc/swanctl/conf.d /etc/swanctl/x509ca\n\n");
    // printf with shell-escaped \n sequences (literal backslash-n, not
    // actual newlines — the golden bytes)
    body.push_str(
        "printf 'charon {\\n  install_routes = yes\\n}\\n' > /var/ipsec/strongswan.conf\n\n",
    );
    body.push_str("cat > /etc/swanctl/x509ca/nordvpn.pem << 'NORD_CA_EOF'\n");
    body.push_str(NORDVPN_IKE2_CA_PEM);
    body.push_str("NORD_CA_EOF\n\n");
    body.push_str("cat > /etc/swanctl/conf.d/nordvpn-ikev2.conf << 'NORD_SWAN_EOF'\n");
    body.push_str(&swanctl);
    body.push('\n');
    body.push_str("NORD_SWAN_EOF\n\n");
    body.push_str("chmod 600 /etc/swanctl/conf.d/nordvpn-ikev2.conf\n\n");
    body.push_str("# charon is not under procd here: start it from rc.local after the network\n");
    body.push_str(
        "grep -q 'nordvpn-ikev2-charon' /etc/rc.local 2>/dev/null || \
         cat >> /etc/rc.local << 'NORD_RC_EOF'\n",
    );
    body.push_str("# nordvpn-ikev2-charon\n");
    body.push_str(bringup);
    body.push('\n');
    body.push_str("NORD_RC_EOF\n\n");
    body.push_str("# also bring it up right now (first boot)\n");
    body.push_str(bringup);
    body.push('\n');
    body.push_str(&format!(
        "echo \"NordVPN IKEv2 staged: server {} ({}), hw_accel={}\"",
        i2.hostname, i2.station, hw_echo
    ));
    let payload = format!(
        "cat > /tmp/nordvpn_ikev2_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/nordvpn_ikev2_setup.sh",
        body.trim_end()
    );
    ops.push(PlanOp::Shell { command: payload });
    // firewall block inline (ikev2 does NOT use the shared verify
    // tail — charon bring-up is rc.local-based; the zone rides the
    // ipsec0 logical interface)
    for pattern in [
        "name='vpn'",
        "dest='vpn'",
        "name='KillSwitch-Reject-NonVPN'",
        "name='Allow-VPN-Management'",
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
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
            ("network".into(), literal("ipsec0".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
    if i2.allow_management {
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
    if i2.kill_switch {
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
    ops.push(PlanOp::Shell {
        command: "nft add rule inet fw4 input_wan udp dport { 500, 4500 } accept comment 'IKE/NAT-T' 2>/dev/null; \
                  nft add rule inet fw4 input_wan meta l4proto esp accept comment 'ESP' 2>/dev/null; true"
            .into(),
    });
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
    ops.push(PlanOp::Shell {
        command: "uci set dhcp.@dnsmasq[0].noresolv='1'".into(),
    });
    let verification = vec![
        VerificationCheck {
            description: "swanctl config present".into(),
            command: "test -f /etc/swanctl/conf.d/nordvpn-ikev2.conf && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "NordVPN CA certificate installed".into(),
            command: "test -f /etc/swanctl/x509ca/nordvpn.pem && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-nordvpn-ikev2".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// The shared 30s wg-handshake fail-open verify tail (base.py parity).
const VERIFY_WG_30S: &str = "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart";

fn runtime_api_vpn_body(
    body_const: &str,
    wg_priv_var: &str,
    route_section: &str,
    readback_provider: &str,
    iface: &str,
    gateway: &str,
    extra_tokens: &[(&str, &str)],
) -> String {
    let mut pairs: Vec<(String, String)> = extra_tokens
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    pairs.push(("__WG_PRIV__".into(), wg_priv_var.to_string()));
    pairs.push(("__IFACE__".into(), iface.to_string()));
    pairs.push(("__GATEWAY__".into(), gateway.to_string()));
    let route = route_block(route_section);
    let readback = readback_block(readback_provider);
    // assemble then single-pass substitute everything at once — the
    // shared JSON helper always leads the script (1.x composition)
    let mut template = VPN_JSON_HELPER_SH.to_string();
    template.push_str(body_const);
    template.push_str(WG_STANZA_SH);
    template.push('\n');
    template.push_str(&route);
    template.push_str("\n\n");
    template.push_str(&readback);
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    substitute_tokens(&template, &refs)
}

fn plan_vpn_ivpn(model: &DeviceModel, iv: &VpnIvpnProfile) -> Result<Plan, Unsupported> {
    iv.validate()?;
    let body = runtime_api_vpn_body(
        IVPN_WG_BODY_SH,
        "$IVPN_PRIV",
        "ivpn_server_route",
        "IVPN",
        &iv.upstream_iface,
        &iv.upstream_gateway,
        &[("__ACCOUNT__", iv.account_id.as_str())],
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
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
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.0.0.53"],
        iv.kill_switch,
        true,
        VERIFY_WG_30S,
    );
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
        profile_id: "vpn-ivpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

fn plan_vpn_mullvad(model: &DeviceModel, mu: &VpnMullvadProfile) -> Result<Plan, Unsupported> {
    mu.validate()?;
    let country_filter = if mu.country.is_empty() {
        String::new()
    } else {
        format!("\"country_code\":\"{}\"", mu.country)
    };
    let body = runtime_api_vpn_body(
        MULLVAD_WG_BODY_SH,
        "$MULLVAD_PRIV",
        "mullvad_server_route",
        "Mullvad",
        &mu.upstream_iface,
        &mu.upstream_gateway,
        &[
            ("__TOKEN__", mu.account_token.as_str()),
            ("__COUNTRY_FILTER__", country_filter.as_str()),
            ("__COUNTRY__", mu.country.as_str()),
        ],
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
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
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.64.0.1"],
        mu.kill_switch,
        true,
        VERIFY_WG_30S,
    );
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
        profile_id: "vpn-mullvad".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

fn plan_vpn_surfshark(model: &DeviceModel, ss: &VpnSurfsharkProfile) -> Result<Plan, Unsupported> {
    ss.validate()?;
    // creds/country/gateway ride the script text verbatim — the
    // validate() charset gates are what make every interpolation a
    // safe payload (no quoting needed, 1.x bytes preserved)
    let country_filter = if ss.country.is_empty() {
        String::new()
    } else {
        format!("country/{}/", ss.country)
    };
    let body = format!(
        "{}{}",
        VPN_JSON_HELPER_SH,
        substitute_tokens(
            SURFSHARK_WG_BODY_SH,
            &[
                ("__USERNAME__", ss.username.as_str()),
                ("__PASSWORD__", ss.password.as_str()),
                ("__COUNTRY_FILTER__", country_filter.as_str()),
                ("__COUNTRY__", ss.country.as_str()),
                ("__IFACE__", ss.upstream_iface.as_str()),
                ("__GATEWAY__", ss.upstream_gateway.as_str()),
            ],
        ),
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    // Clean baseline (AGENTS.md, Codex #604 P1 round 4): aborted runs
    // leave /tmp/.uci staging debris — revert before staging so the
    // later commits cannot make unrelated changes permanent.
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
        // runtime-API script needs wg tooling + kmod on vanilla images
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        // the script authenticates via curl (Codex #604 P2) — not in
        // every base image
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared composition (zone on wg0, management on) + Surfshark DNS
    // pair in the 1.x order + the 30s wg handshake verify tail
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["162.252.172.57", "149.154.159.92"],
        ss.kill_switch,
        true,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
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
        profile_id: "vpn-surfshark".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// Generic OpenVPN client — port of the 1.x `vpn-openvpn` preset
/// (`scripts/use_cases/vpn_providers/openvpn.py`, 1.x marks it
/// UNTESTED — same evidence bar here). For any provider offering
/// .ovpn files (ExpressVPN, ProtonVPN, CyberGhost…): the plan writes
/// the inline config (+optional credentials, chmod 600) via quoted
/// heredocs, shapes the `openvpn.vpn_client` service + `vpn_if`
/// network interface, reuses the shared VPN firewall block (zone,
/// lan→vpn forwarding, management rule, kill switch), and pairs the
/// kill switch with base.py's 45-second tun-verify fail-open loop —
/// which the 1.x preset FORGOT (a bad config + kill switch bricked
/// WAN; fixed Python-side with this port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnOpenvpnProfile {
    /// Inline .ovpn configuration text (1.x required param). Must not
    /// contain a line `OVPNEOF` — it would escape the quoted heredoc
    /// and run as live script (injection gate, fixed with this port).
    pub ovpn_config: String,
    /// VPN username (optional; single line — rides the UCI override).
    pub username: String,
    /// VPN password (optional; single line — rides the UCI override).
    pub password: String,
    /// Transport protocol (1.x choice set: `udp`, `tcp`).
    pub proto: String,
    /// Block all non-VPN traffic if the tunnel drops (1.x default on;
    /// paired with the fail-open verify loop).
    pub kill_switch: bool,
}

impl Default for VpnOpenvpnProfile {
    fn default() -> Self {
        Self {
            ovpn_config: String::new(),
            username: String::new(),
            password: String::new(),
            proto: "udp".into(),
            kill_switch: true,
        }
    }
}

impl VpnOpenvpnProfile {
    /// Heredoc-terminator + choice gates mirroring the Python-side
    /// `_resolve_params` fix: an `OVPNEOF` line escapes the quoted
    /// heredoc (pbr-class injection), newlines break the UCI
    /// credential options, and `proto` lands in a rendered comment.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.ovpn_config.is_empty() {
            return Err(Unsupported::InvalidParams(
                "ovpn_config is required (inline .ovpn text)".into(),
            ));
        }
        if self.ovpn_config.lines().any(|l| l.trim() == "OVPNEOF") {
            return Err(Unsupported::InvalidParams(
                "ovpn_config must not contain a line 'OVPNEOF' (heredoc terminator)".into(),
            ));
        }
        for (field, value) in [("username", &self.username), ("password", &self.password)] {
            if value.contains('\n') || value.contains('\r') {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must be a single line"
                )));
            }
        }
        if !matches!(self.proto.as_str(), "udp" | "tcp") {
            return Err(Unsupported::InvalidParams(
                "proto must be udp or tcp".into(),
            ));
        }
        Ok(())
    }
}

///
/// Pricing purity delta (documented honestly): 1.x auto-fetches the
/// sats/USD rate from mempool.space at BUILD time when
/// `fx_sats_per_usd` is unset; the 2.x planner is I/O-free by
/// invariant, so derivation REQUIRES an explicit rate — pass the
/// 1.x-resolved value (the derivation math itself is identical and
/// unit-pinned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TollgateProfile {
    /// Nodogsplash gateway name shown to clients (empty = default).
    pub gateway_name: String,
    /// Nodogsplash gateway domain (empty = default).
    pub gateway_domain: String,
    /// Client identification method (1.x choice set: `mac`, `token`,
    /// `ip`).
    pub clientid: String,
    /// Expose SSH (tcp 22) to pre-auth clients via users_to_router.
    pub allow_lan_ssh: bool,
    /// Install the ifup hotplug hook that restarts tollgate-wrt.
    pub install_hotplug: bool,
    /// Interface whose ifup restarts tollgate (1.x default `wwan`;
    /// `shell_safe::interface_name` charset — it executes inside the
    /// installed script's double-quoted test, the pbr-class gate).
    pub hotplug_interface: String,
    /// Cashu mint URL (empty = skip payment section).
    pub mint_url: String,
    /// Lightning address for payouts (empty = skip).
    pub lightning_address: String,
    /// Price in sats per minute (1.x default 1; rendered only when
    /// different from 1).
    pub price_per_minute: u32,
    /// Direct byte price in sats/MiB (0 = derive from upstream cost).
    pub price_sats_per_mib: u32,
    /// Upstream data cost, USD per GB, as a decimal string (1.x
    /// float param kept as a string for plan equality).
    pub upstream_usd_per_gb: String,
    /// Cost multiplier applied to the upstream cost (decimal string;
    /// 1.x default 2.0).
    pub markup: String,
    /// Sats per USD for the derivation (REQUIRED when deriving — see
    /// the purity delta in the type docs).
    pub fx_sats_per_usd: u32,
}

impl Default for TollgateProfile {
    fn default() -> Self {
        Self {
            gateway_name: String::new(),
            gateway_domain: String::new(),
            clientid: "mac".into(),
            allow_lan_ssh: false,
            install_hotplug: true,
            hotplug_interface: "wwan".into(),
            mint_url: String::new(),
            lightning_address: String::new(),
            price_per_minute: 1,
            price_sats_per_mib: 0,
            upstream_usd_per_gb: "0".into(),
            markup: "2.0".into(),
            fx_sats_per_usd: 0,
        }
    }
}

impl TollgateProfile {
    /// 1.x gates ported: the `hotplug_interface` charset (runtime
    /// injection in the installed ifup script), the `clientid` choice
    /// set, and the pricing-derivation bounds (`markup` must be > 0;
    /// `upstream_usd_per_gb` must parse). The explicit-fx requirement
    /// is the 2.x purity delta (see type docs).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        };
        if !iface_ok(&self.hotplug_interface) {
            return Err(Unsupported::InvalidParams(
                "hotplug_interface contains unsafe characters".into(),
            ));
        }
        if !matches!(self.clientid.as_str(), "mac" | "token" | "ip") {
            return Err(Unsupported::InvalidParams(
                "clientid must be one of: mac, token, ip".into(),
            ));
        }
        let upstream: f64 = self.upstream_usd_per_gb.parse().map_err(|_| {
            Unsupported::InvalidParams("upstream_usd_per_gb must be a number".into())
        })?;
        // NaN skips every comparison gate below (all false) and would
        // clamp to a 1-sat price in the derivation (Codex #601 P2 r4)
        if !upstream.is_finite() {
            return Err(Unsupported::InvalidParams(
                "upstream_usd_per_gb must be a finite number".into(),
            ));
        }
        if upstream < 0.0 {
            return Err(Unsupported::InvalidParams(
                "upstream_usd_per_gb must be >= 0".into(),
            ));
        }
        let markup: f64 = self
            .markup
            .parse()
            .map_err(|_| Unsupported::InvalidParams("markup must be a number".into()))?;
        if !markup.is_finite() {
            return Err(Unsupported::InvalidParams(
                "markup must be a finite number".into(),
            ));
        }
        if self.price_sats_per_mib == 0 && upstream > 0.0 {
            if markup <= 0.0 {
                return Err(Unsupported::InvalidParams("markup must be > 0".into()));
            }
            if self.fx_sats_per_usd == 0 {
                return Err(Unsupported::InvalidParams(
                    "fx_sats_per_usd is required for price derivation (the 1.x \
                     mempool.space auto-fetch is a build-time I/O the I/O-free \
                     2.x planner refuses; pass the resolved rate)"
                        .into(),
                ));
            }
        }
        // shared range gate: an out-of-range derived price must be
        // rejected HERE too, not only at render (Codex #601 P2 round 3)
        self.derived_price_checked()?;
        Ok(())
    }

    /// 1.x `_derive_price_sats_per_mib` parity (pure half): explicit
    /// price wins; else derive `upstream/1024 * fx * markup`, ceil,
    /// min 1. `None` = no pricing block. The ceiling is a manual
    /// truncate-then-bump — `f64::ceil` is std-only and this crate
    /// cross-builds no_std (CI thumbv7em gate). Extreme inputs that
    /// would overflow the u32 price are REJECTED (a saturating cast
    /// plus the bump wraps to ZERO in release builds — a free-access
    /// price on a payment gateway; Codex #601 P2 round 3).
    fn derived_price_checked(&self) -> Result<Option<(u32, &'static str)>, Unsupported> {
        if self.price_sats_per_mib > 0 {
            return Ok(Some((
                self.price_sats_per_mib,
                "explicit price_sats_per_mib",
            )));
        }
        let upstream: f64 = match self.upstream_usd_per_gb.parse() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if upstream <= 0.0 {
            return Ok(None);
        }
        let markup: f64 = match self.markup.parse() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let price = upstream / 1024.0 * self.fx_sats_per_usd as f64 * markup;
        // check the UNCLAMPED product: f64::max(NaN, 1.0) returns 1.0,
        // so clamping first would launder a NaN into a 1-sat price
        // (Codex #601 P2 round 4)
        if !price.is_finite() || price <= 0.0 {
            return Err(Unsupported::InvalidParams(
                "derived price is not a finite positive number".into(),
            ));
        }
        let price = price.max(1.0);
        if price >= u32::MAX as f64 {
            return Err(Unsupported::InvalidParams(
                "derived price exceeds the supported sats/MiB range — refusing to \
                 plan a price that could wrap to zero"
                    .into(),
            ));
        }
        let truncated = price as u32;
        let ceil = if price > truncated as f64 {
            truncated + 1
        } else {
            truncated
        };
        Ok(Some((ceil, "derived")))
    }
}

/// RFC 1918 isolation for TollGate public WiFi — port of the tested
/// 1.x `tollgate-security` preset (`scripts/use_cases/
/// tollgate_security.py`). Four named lan→wan DROP rules (RFC 1918
/// A/B/C + link-local) plus WiFi client isolation on both default
/// radios. The router's own OUTPUT chain is untouched by design —
/// payments, DNS, and updates keep flowing. No params, no
/// interpolation; named firewall sections re-set in place (idempotent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TollgateSecurityProfile;

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

/// NordVPN via OpenVPN (tun0) — port of the tested 1.x
/// `vpn-nordvpn-openvpn` preset (`scripts/use_cases/vpn_providers/
/// nordvpn.py`, hardware-verified 2026-10-08 on COVR-X1860 @ 25.12.5).
/// Template-faithful to the official per-server .ovpn configs: multi-port
/// remotes, tls-auth with the NordVPN-wide static key, x509 CN pinning.
/// 1.x resolves the SERVICE CREDENTIALS and the server at BUILD time
/// from the access token; that resolution stays 1.x (M7) — this
/// profile carries the resolved statics (same contract as the
/// nordlynx profile; goldens use stubbed resolution, no real creds in
/// git).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNordvpnOpenvpnProfile {
    /// Resolved service username (heredoc line — control-char and
    /// delimiter gates in validate()).
    pub username: String,
    /// Resolved service password (same gates).
    pub password: String,
    /// Server station IP (the remotes target).
    pub station: String,
    /// Server hostname — must be from the SAME server object as the
    /// station or the x509 CN pin rejects the TLS peer.
    pub hostname: String,
    /// `udp` or `tcp` (1.x technology openvpn-udp/openvpn-tcp).
    pub proto: String,
    /// OpenVPN cipher (1.x default AES-256-CBC; GCM negotiable).
    pub cipher: String,
    /// Upstream gateway for nothing here — kept for symmetry: this
    /// preset uses no gateway pin (template-faithful).
    pub kill_switch: bool,
    /// Accept SSH/LuCI from the VPN zone (default on).
    pub allow_management: bool,
}

impl Default for VpnNordvpnOpenvpnProfile {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            station: String::new(),
            hostname: String::new(),
            proto: "udp".into(),
            cipher: "AES-256-CBC".into(),
            kill_switch: true,
            allow_management: true,
        }
    }
}

impl VpnNordvpnOpenvpnProfile {
    /// 1.x validates nothing (values came from its own API calls);
    /// this payload interpolates them into quoted-heredoc lines and
    /// uci values, so the port gates the mwan3/#448 class: no control
    /// characters and no heredoc delimiters in the credentials,
    /// station must be IPv4, hostname on the NordVPN hostname charset,
    /// proto ∈ {udp, tcp}, cipher alnum+dash.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let ctrl = |v: &str| v.chars().any(|c| c.is_ascii_control());
        for (field, value) in [("username", &self.username), ("password", &self.password)] {
            if value.is_empty() {
                return Err(Unsupported::InvalidParams(format!("{field} is required")));
            }
            if ctrl(value) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must not contain control characters"
                )));
            }
            if matches!(
                value.as_str(),
                "VPN_SETUP_EOF" | "NORD_CA_EOF" | "NORD_TA_EOF" | "NORD_AUTH_EOF"
            ) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must not equal a heredoc delimiter"
                )));
            }
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
        if !ipv4(&self.station) {
            return Err(Unsupported::InvalidParams(
                "station must be an IPv4 address".into(),
            ));
        }
        if self.hostname.is_empty()
            || !self
                .hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        {
            return Err(Unsupported::InvalidParams(
                "hostname must be a NordVPN server hostname".into(),
            ));
        }
        if !matches!(self.proto.as_str(), "udp" | "tcp") {
            return Err(Unsupported::InvalidParams(
                "proto must be udp or tcp".into(),
            ));
        }
        if self.cipher.is_empty()
            || !self
                .cipher
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(Unsupported::InvalidParams(
                "cipher contains unsafe characters".into(),
            ));
        }
        Ok(())
    }
}

/// Private Internet Access via WireGuard — port of the tested 1.x
/// `vpn-pia` preset (`scripts/use_cases/vpn_providers/pia.py`,
/// hardware-tested 24.10.4 MediaTek Filogic, Czechia region). Unlike
/// the nordvpn family this is a RUNTIME-API script: the device
/// generates its own WireGuard keypair, exchanges the PIA auth token,
/// registers the key with the regional server, and configures wg0
/// from the response — all in one payload. The host carries only the
/// account credentials and routing pins. PIA tokens expire ~7 days:
/// reboot persistence relies on the wg0 uci (re-authenticated on
/// ifup) — the 1.x autostart init note applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPiaProfile {
    /// PIA account username (the p-number). Rides sh-quoted into
    /// `curl -u` — validate() rejects control characters (1.x sh_quote
    /// raised on newlines; the port closes the wider charset hole).
    pub username: String,
    /// PIA account password (same gate).
    pub password: String,
    /// PIA region slug (netherlands/czech/…): a hostname label in the
    /// addKey URL — alphanumeric gate.
    pub region: String,
    /// Upstream gateway IP: pins the server route so tunnel traffic
    /// never routes via wg0 itself (circular routing guard).
    pub upstream_gateway: String,
    /// Upstream interface name for the pin (1.x default wwan).
    pub upstream_iface: String,
    /// Block all non-VPN traffic if the tunnel drops (1.x default on;
    /// the 30s handshake tail auto-removes it when auth or addKey
    /// fails, restoring WAN).
    pub kill_switch: bool,
    /// Accept SSH/LuCI from the VPN zone (1.x passes the default on).
    pub allow_management: bool,
}

impl Default for VpnPiaProfile {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            region: "netherlands".into(),
            upstream_gateway: String::new(),
            upstream_iface: "wwan".into(),
            kill_switch: true,
            allow_management: true,
        }
    }
}

impl VpnPiaProfile {
    /// 1.x validates via sh_quote raising on control chars (newline
    /// tested in test_vpn_provider_transport); everything else was
    /// ungated. The port gates the full mwan3/#448 class: creds
    /// non-empty + no control chars, region alphanumeric (hostname
    /// label in a double-quoted URL), gateway IPv4, iface charset.
    pub fn validate(&self) -> Result<(), Unsupported> {
        let ctrl = |v: &str| v.chars().any(|c| c.is_ascii_control());
        for (field, value) in [("username", &self.username), ("password", &self.password)] {
            if value.is_empty() {
                return Err(Unsupported::InvalidParams(format!("{field} is required")));
            }
            if ctrl(value) {
                return Err(Unsupported::InvalidParams(format!(
                    "{field} must not contain control characters"
                )));
            }
        }
        if self.region.is_empty() || !self.region.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Unsupported::InvalidParams(
                "region must be an alphanumeric PIA region slug".into(),
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
        if !ipv4(&self.upstream_gateway) {
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

const PIA_WG_BODY_SH: &str = concat!(
    "\n",
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "# Authenticate with PIA — get auth token\n",
    "curl -fs -m 15 -u __CREDS__ \\\n",
    "    \"https://www.privateinternetaccess.com/gtoken/generateToken\" \\\n",
    "    -o /tmp/vpn_token.json\n",
    "PIA_TOKEN=$(cat /tmp/vpn_token.json | json_get token)\n",
    "[ -n \"$PIA_TOKEN\" ] || { echo 'PIA: auth failed — no token in API response'; exit 1; }\n",
    "\n",
    "# URL-encode token: PIA tokens contain +, /, = that break curl\n",
    "ENC_TOKEN=$(echo \"$PIA_TOKEN\" | sed 's/+/%2B/g; s/=/%3D/g; s|/|%2F|g')\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG key with regional server\n",
    "curl -fs -m 15 -k \\\n",
    "    \"https://__REGION__.privacy.network:1337/addKey?pt=${ENC_TOKEN}&pubkey=${WG_PUB}\" \\\n",
    "    -o /tmp/vpn_addkey.json\n",
    "\n",
    "# Parse server response\n",
    "SERVER_KEY=$(cat /tmp/vpn_addkey.json | json_get server_key)\n",
    "SERVER_IP=$(cat /tmp/vpn_addkey.json | json_get server_ip)\n",
    "SERVER_PORT=$(cat /tmp/vpn_addkey.json | json_get server_port)\n",
    "PEER_IP=$(cat /tmp/vpn_addkey.json | json_get peer_ip)\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is complete\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] && [ -n \"$SERVER_PORT\" ] && [ -n \"$PEER_IP\" ] \\\n",
    "    || { echo 'PIA: addKey response incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "PIA_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"$PIA_PRIV\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
    "\n",
    "# Static route: prevent circular routing through VPN tunnel\n",
    "uci -q delete network.pia_server_route\n",
    "uci set network.pia_server_route=route\n",
    "uci set network.pia_server_route.interface='__IFACE__'\n",
    "uci set network.pia_server_route.target=\"${SERVER_IP}\"\n",
    "uci set network.pia_server_route.netmask='255.255.255.255'\n",
    "uci set network.pia_server_route.gateway='__GATEWAY__'\n",
);
fn plan_vpn_pia(model: &DeviceModel, pia: &VpnPiaProfile) -> Result<Plan, Unsupported> {
    pia.validate()?;
    // creds ride sh-quoted into `curl -u` (1.x sh_quote parity — the
    // same escaping render_shell uses for uci literals); the body is
    // the verbatim 1.x script with sentinel tokens for the four
    // interpolations (validate()'s gates make them payload-safe).
    // Single-pass substitution: chained `.replace()` would rewrite
    // token-shaped payloads inside the quoted creds (the surfshark
    // #604-P2 class, applied here by the hardening audit).
    let creds = shell_quote(&format!("{}:{}", pia.username, pia.password));
    let body = format!(
        "{}{}",
        VPN_JSON_HELPER_SH,
        substitute_tokens(
            PIA_WG_BODY_SH,
            &[
                ("__CREDS__", creds.as_str()),
                ("__REGION__", pia.region.as_str()),
                ("__IFACE__", pia.upstream_iface.as_str()),
                ("__GATEWAY__", pia.upstream_gateway.as_str()),
            ],
        ),
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        // runtime-API script needs wg tooling + kmod on vanilla images
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        // the script's first act is `curl -u` auth (hardening audit:
        // the surfshark #604-P2 gap, same class here) — not in every
        // base image
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared composition + the 30s wg handshake verify TAIL; PIA DNS
    // pair in the 1.x order (243 first)
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.0.0.243", "10.0.0.242"],
        pia.kill_switch,
        pia.allow_management,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
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
        profile_id: "vpn-pia".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
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
    /// Full-tunnel WireGuard client for the vps-on-demand Cashu VPN
    /// exit (params come from the paid `POST /peer` response).
    CashuVpnClient(CashuVpnClientProfile),
    /// NordVPN via NordLynx (WireGuard; resolved statics carried).
    VpnNordvpn(VpnNordvpnProfile),
    /// NordVPN via OpenVPN (service-credential statics carried).
    VpnNordvpnOpenvpn(VpnNordvpnOpenvpnProfile),
    /// Private Internet Access via WireGuard (runtime-API script).
    VpnPia(VpnPiaProfile),
    /// MPTCP connection bonding via BondingShouldBeFree (single remote
    /// installer; needs an MPTCP kernel, 25.12+/SNAPSHOT).
    MptcpBonding(MptcpBondingProfile),
    /// Generic OpenVPN client for providers without a WireGuard API
    /// (inline .ovpn config; 1.x marks the preset untested).
    VpnOpenvpn(VpnOpenvpnProfile),
    /// Surfshark WireGuard VPN (runtime-API script; 1.x marks the
    /// preset untested).
    VpnSurfshark(VpnSurfsharkProfile),
    /// IVPN WireGuard VPN (runtime-API script; 1.x marks the preset
    /// untested).
    VpnIvpn(VpnIvpnProfile),
    /// Mullvad WireGuard VPN (runtime-API script; 1.x marks the
    /// preset untested).
    VpnMullvad(VpnMullvadProfile),
    /// Self-announcing WireGuard server: Nostr Europa listing
    /// publisher (pairs with wireguard-server; 1.x marks it untested).
    VpnNode(VpnNodeProfile),
    /// NordVPN IKEv2/IPsec via strongSwan (resolved statics; 1.x
    /// marks the preset's IKEv2 path hardware-tested).
    VpnNordvpnIke2(VpnNordvpnIke2Profile),
    /// OpenTollGate payment gateway (flash-time portal + payment
    /// config; the ipk deploy is a host-side post-flash step).
    Tollgate(TollgateProfile),
    /// RFC 1918 isolation for TollGate public WiFi.
    TollgateSecurity(TollgateSecurityProfile),
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
            Profile::CashuVpnClient(_) => "cashu-vpn-client",
            Profile::VpnNordvpn(_) => "vpn-nordvpn",
            Profile::VpnNordvpnOpenvpn(_) => "vpn-nordvpn-openvpn",
            Profile::VpnPia(_) => "vpn-pia",
            Profile::MptcpBonding(_) => "mptcp-bonding",
            Profile::VpnOpenvpn(_) => "vpn-openvpn",
            Profile::VpnSurfshark(_) => "vpn-surfshark",
            Profile::VpnIvpn(_) => "vpn-ivpn",
            Profile::VpnMullvad(_) => "vpn-mullvad",
            Profile::VpnNode(_) => "vpn-node",
            Profile::VpnNordvpnIke2(_) => "vpn-nordvpn-ikev2",
            Profile::Tollgate(_) => "tollgate",
            Profile::TollgateSecurity(_) => "tollgate-security",
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
            Profile::CashuVpnClient(_) => &["ethernet"],
            Profile::VpnNordvpn(_) => &[],
            Profile::VpnNordvpnOpenvpn(_) => &[],
            Profile::VpnPia(_) => &[],
            Profile::MptcpBonding(_) => &[],
            Profile::VpnOpenvpn(_) => &[],
            Profile::VpnSurfshark(_) => &[],
            Profile::VpnIvpn(_) => &[],
            Profile::VpnMullvad(_) => &[],
            Profile::VpnNode(_) => &[],
            Profile::VpnNordvpnIke2(_) => &[],
            Profile::Tollgate(_) => &[],
            Profile::TollgateSecurity(_) => &["wifi"],
        }
    }

    /// Hard OpenWrt floor (major.minor) the profile requires, if any.
    /// Enforced against `model.openwrt.version` in [`plan_profile`];
    /// a version without a minor part (e.g. `25`) passes on major.
    #[must_use]
    pub fn min_openwrt(&self) -> Option<(u32, u32)> {
        match self {
            // MPTCP kernels: pre-25.12 OpenWrt either lacks CONFIG_MPTCP
            // (24.10) or is unqualified; 25.12 also matches the
            // mptcp-bonding preset's tested surface (kernel 6.12.x —
            // CVE-2026-98432 patched at 6.12.113+)
            Profile::MptcpBonding(_) => Some((25, 12)),
            _ => None,
        }
    }
}

/// Parse an OpenWrt version string into (major, minor?) — `24.10.2` →
/// `(24, Some(10))`, `25` → `(25, None)`, `snapshot`/junk → `None`.
fn parse_openwrt_version(v: &str) -> Option<(u32, Option<u32>)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|m| m.parse().ok());
    Some((major, minor))
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
    /// Non-fatal advisories (e.g. the 24.x deprecation warning) —
    /// rendered as comments, never as commands.
    pub warnings: Vec<String>,
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
    /// The model's OpenWrt release is below the profile's hard floor
    /// (e.g. mptcp-bonding requires 25.12+ — pre-25.12 kernels either
    /// lack MPTCP entirely or carry unpatched CVEs).
    OpenWrtTooOld {
        /// Version the model declares (e.g. `24.10.2`).
        have: String,
        /// Minimum the profile requires (e.g. `25.12`).
        need: String,
    },
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
            Unsupported::OpenWrtTooOld { have, need } => {
                write!(f, "OpenWrt {have} is below this profile's floor {need}")
            }
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

/// Plan against the device's AUTHENTICATED release when the apply path
/// has it (`/etc/openwrt_release` DISTRIB_RELEASE via fingerprint) —
/// the species-level model version is a qualification claim that goes
/// stale the moment a device is sysupgraded (Codex #606 P2: a device
/// upgraded to 25.12 under a `version: "24"` model was refused despite
/// running a supported kernel). Unparseable live values (local builds)
/// fall back to the model claim; `None` is offline planning.
pub fn plan_profile_for_device(
    state: &DeviceState,
    model: &DeviceModel,
    profile: &Profile,
    live_release: Option<&str>,
) -> Result<Plan, Unsupported> {
    if let Some(live) = live_release {
        if parse_openwrt_version(live).is_some() {
            let mut live_model = model.clone();
            live_model.openwrt.version = live.to_string();
            return plan_profile(state, &live_model, profile);
        }
    }
    plan_profile(state, model, profile)
}

/// Plan the operations to reach a profile's desired state, judged
/// against the species-level model claim (offline planning — prefer
/// [`plan_profile_for_device`] when the live release is known).
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
    if let Some((need_major, need_minor)) = profile.min_openwrt() {
        if let Some((major, minor)) = parse_openwrt_version(&model.openwrt.version) {
            let below = major < need_major
                || (major == need_major && minor.is_some_and(|m| m < need_minor));
            if below {
                return Err(Unsupported::OpenWrtTooOld {
                    have: model.openwrt.version.clone(),
                    need: format!("{need_major}.{need_minor}"),
                });
            }
        }
        // unparseable (e.g. `snapshot`): cannot judge — the runtime
        // kernel check in the plan's verification covers reality
    }
    let mut plan = match profile {
        Profile::Sqm(sqm) => plan_sqm(model, sqm),
        Profile::Doh(doh) => plan_doh(model, doh),
        Profile::Tether(tether) => plan_tether(model, tether),
        Profile::WireguardClient(wg) => plan_wireguard_client(model, wg),
        Profile::WireguardServer(wg) => plan_wireguard_server(model, wg),
        Profile::CashuVpnClient(wg) => plan_cashu_vpn_client(model, wg),
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
        Profile::VpnNordvpnOpenvpn(nv) => plan_vpn_nordvpn_openvpn(model, nv),
        Profile::VpnPia(pia) => plan_vpn_pia(model, pia),
        Profile::MptcpBonding(mp) => plan_mptcp_bonding(model, mp),
        Profile::VpnOpenvpn(vo) => plan_vpn_openvpn(model, vo),
        Profile::VpnSurfshark(ss) => plan_vpn_surfshark(model, ss),
        Profile::VpnIvpn(iv) => plan_vpn_ivpn(model, iv),
        Profile::VpnMullvad(mu) => plan_vpn_mullvad(model, mu),
        Profile::VpnNode(vn) => plan_vpn_node(model, vn),
        Profile::VpnNordvpnIke2(i2) => plan_vpn_nordvpn_ike2(model, i2),
        Profile::Tollgate(tg) => plan_tollgate(model, tg),
        Profile::TollgateSecurity(ts) => plan_tollgate_security(model, ts),
    }?;
    // 24.x deprecation advisory (warning, not refusal — policy: warn
    // and plan the upgrade; see the deprecation tracking issue):
    // 24.10 kernels (6.6) sit past end-of-support with unpatched CVEs
    // (e.g. CVE-2026-98432, fixed at 6.6.159) and most presets are
    // 25.x-qualified.
    if let Some((24, _)) = parse_openwrt_version(&model.openwrt.version) {
        plan.warnings.push(
            "OpenWrt 24.x is past end-of-support: known kernel CVEs unpatched \
             (CVE-2026-98432 fixed only at 6.6.159+) and 25.x is the \
             qualified release family — plan an upgrade"
                .into(),
        );
    }
    Ok(plan)
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
        warnings: Vec::new(),
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

/// Cashu VPN kill-switch guard — 1.x `cashu_vpn_client.py` post-apply
/// loop: wait up to 30 s for a handshake, else remove the kill switch so
/// the site regains WAN (fail-open by design, like the wireguard-client
/// guard above).
const CASHU_VPN_KILLSWITCH_VERIFY: &str = "i=0; while [ $i -lt 30 ]; do \
if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then \
echo 'Cashu VPN kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; \
echo 'Cashu VPN kill-switch: tunnel failed \u{2014} removing kill switch to restore WAN'; \
uci delete firewall.cashu_vpn_killswitch; uci commit firewall; fw4 restart";

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
        warnings: Vec::new(),
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
        // Same read-back class as the #524 P1 (caught in cashu-vpn,
        // fixed here too): the committed address must be read back.
        // green with an unnumbered interface.
        VerificationCheck {
            description: "tunnel address persisted".into(),
            command: "uci -q get network.wg0.addresses".into(),
            expect_contains: wg.address.clone(),
        },
    ];
    Ok(Plan {
        profile_id: "wireguard-client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
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
        warnings: Vec::new(),
    })
}

fn plan_cashu_vpn_client(
    model: &DeviceModel,
    wg: &CashuVpnClientProfile,
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
                ("addresses".into(), literal(wg.peer_ip.clone())),
            ],
        },
    ];
    for token in wg.dns.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        ops.push(PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "dns".into(),
            value: token.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "network".into(),
        section: "wg0_peer".into(),
        section_type: "wireguard_wg0".into(),
        options: vec![
            ("public_key".into(), literal(wg.peer_public_key.clone())),
            ("endpoint_host".into(), literal(wg.server_host.clone())),
            ("endpoint_port".into(), literal(wg.server_port.to_string())),
            ("allowed_ips".into(), literal(wg.allowed_ips.clone())),
            ("route_allowed_ips".into(), literal("1".into())),
            ("persistent_keepalive".into(), literal("25".into())),
        ],
    });
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
            section: "cashu_vpn_zone".into(),
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
            section: "cashu_vpn_fwd".into(),
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
            section: "cashu_vpn_killswitch".into(),
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
                "echo 'Cashu VPN client configured: {}:{} (peer_ip={})'",
                wg.server_host, wg.server_port, wg.peer_ip
            ),
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::Shell {
            command: CASHU_VPN_KILLSWITCH_VERIFY.into(),
        });
    }
    // The kill-switch rule is intentionally NOT verified post-apply: the
    // guard loop removes it when no handshake appears (fail-open).
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "peer endpoint persisted".into(),
            command: "uci -q get network.wg0_peer.endpoint_host".into(),
            expect_contains: wg.server_host.clone(),
        },
        VerificationCheck {
            description: "peer public key persisted".into(),
            command: "uci -q get network.wg0_peer.public_key".into(),
            expect_contains: wg.peer_public_key.clone(),
        },
        // Codex P1 (#524): the tunnel address was committed but never
        // read back — a failed/typo'd addresses value left the plan
        // green with an unnumbered interface.
        VerificationCheck {
            description: "tunnel address persisted".into(),
            command: "uci -q get network.wg0.addresses".into(),
            expect_contains: wg.peer_ip.clone(),
        },
    ];
    Ok(Plan {
        profile_id: "cashu-vpn-client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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

/// The vpn-provider family's shared firewall-zone/DNS/verify tail —
/// 1.x `vpn_providers/base.py::build_{firewall,dns,verify}_ops`, byte
/// parity. Named sections + `CleanupUciSections` keep re-runs and
/// technology switches (wg → openvpn) idempotent: the family zone name
/// (`name='vpn'`) lets one technology's setup retire another's rules.
/// `verify_line` is the kind-specific failure TAIL (wg handshake vs
/// tun-address probe) that removes the kill switch when the tunnel
/// never comes up.
#[allow(clippy::too_many_arguments)]
fn push_vpn_shared_ops(
    ops: &mut Vec<PlanOp>,
    iface: &str,
    dns_servers: &[&str],
    kill_switch: bool,
    allow_management: bool,
    verify_line: &str,
) {
    let literal = |v: String| UciValue::Literal(v);
    for (config, pattern) in [
        ("firewall", "name='vpn'"),
        ("firewall", "dest='vpn'"),
        ("firewall", "name='KillSwitch-Reject-NonVPN'"),
        ("firewall", "name='Allow-VPN-Management'"),
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: config.into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
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
            ("network".into(), literal(iface.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
    if allow_management {
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
    if kill_switch {
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
    for dns in dns_servers {
        ops.push(PlanOp::Shell {
            command: format!("uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true"),
        });
        ops.push(PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: (*dns).into(),
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
    if kill_switch {
        ops.push(PlanOp::Shell {
            command: verify_line.into(),
        });
    }
}

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
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "openvpn-openssl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition (byte-identical tail: cleanup, zone,
    // forwarding, management/kill-switch, tunnel DNS, restarts, and
    // the 45s tun-address verify TAIL that removes the kill switch
    // when the tunnel never comes up)
    push_vpn_shared_ops(
        &mut ops,
        "tun0",
        &["10.0.0.241", "10.0.0.242", "10.0.0.243"],
        pia.kill_switch,
        pia.allow_management,
        "i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
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
        warnings: Vec::new(),
    })
}

const VPN_JSON_HELPER_SH: &str = concat!(
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
    "    VPN_GW=$(ip -4 route show default dev {iface} 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')\n",
    "    [ -z \"$VPN_GW\" ] && VPN_GW=$(ip -4 route show default 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')\n",
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
        // single-pass substitution (hardening audit: the #604-P2
        // token-collision class — validated values, defense in depth)
        substitute_tokens(
            NORD_GATEWAY_DISCOVER_SH,
            &[
                ("{iface}", nv.upstream_iface.as_str()),
                ("{route_ip}", route_ip.as_str()),
            ],
        )
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
        JSON_HELPER = VPN_JSON_HELPER_SH,
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
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition (byte-identical tail) + the 30s wg
    // handshake verify TAIL that removes the kill switch on failure
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["103.86.96.100", "103.86.99.100"],
        nv.kill_switch,
        nv.allow_management,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
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
        warnings: Vec::new(),
    })
}

const NORDVPN_OPENVPN_CA: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ\n",
    "MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2\n",
    "MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV\n",
    "BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI\n",
    "hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF\n",
    "kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr\n",
    "XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU\n",
    "eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV\n",
    "skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu\n",
    "MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA\n",
    "37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR\n",
    "hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s\n",
    "Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy\n",
    "WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6\n",
    "MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST\n",
    "LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG\n",
    "SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g\n",
    "nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/\n",
    "k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S\n",
    "DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/\n",
    "pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo\n",
    "k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp\n",
    "+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd\n",
    "NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa\n",
    "wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC\n",
    "VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S\n",
    "PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==\n",
    "-----END CERTIFICATE-----\n",
);
const NORDVPN_OPENVPN_TLS_AUTH: &str = concat!(
    "#\n",
    "# 2048 bit OpenVPN static key\n",
    "#\n",
    "-----BEGIN OpenVPN Static key V1-----\n",
    "e685bdaf659a25a200e2b9e39e51ff03\n",
    "0fc72cf1ce07232bd8b2be5e6c670143\n",
    "f51e937e670eee09d4f2ea5a6e4e6996\n",
    "5db852c275351b86fc4ca892d78ae002\n",
    "d6f70d029bd79c4d1c26cf14e9588033\n",
    "cf639f8a74809f29f72b9d58f9b8f5fe\n",
    "fc7938eade40e9fed6cb92184abb2cc1\n",
    "0eb1a296df243b251df0643d53724cdb\n",
    "5a92a1d6cb817804c4a9319b57d53be5\n",
    "80815bcfcb2df55018cc83fc43bc7ff8\n",
    "2d51f9b88364776ee9d12fc85cc7ea5b\n",
    "9741c4f598c485316db066d52db4540e\n",
    "212e1518a9bd4828219e24b20d88f598\n",
    "a196c9de96012090e333519ae18d3509\n",
    "9427e7b372d348d352dc4c85e18cd4b9\n",
    "3f8a56ddb2e64eb67adfc9b337157ff4\n",
    "-----END OpenVPN Static key V1-----\n",
);
const NORDVPN_OPENVPN_PORTS: &str = "1231 1232 1233 1234";

fn plan_vpn_nordvpn_openvpn(
    model: &DeviceModel,
    nv: &VpnNordvpnOpenvpnProfile,
) -> Result<Plan, Unsupported> {
    nv.validate()?;
    let remotes = NORDVPN_OPENVPN_PORTS
        .split_whitespace()
        .map(|port| {
            format!(
                "uci add_list openvpn.nordvpn.remote='{} {port}'",
                nv.station
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    // whole setup rides ONE heredoc (1.x transport_sh): CA, tls-auth
    // and credentials land as static files; validate()'s gates make
    // the credential lines safe
    let body = format!(
        concat!(
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n",
            "# Tear down any previous OpenVPN instance\n",
            "uci -q delete openvpn.nordvpn\n",
            "\n",
            "mkdir -p /etc/openvpn\n",
            "cat > /etc/openvpn/nordvpn.ca << 'NORD_CA_EOF'\n",
            "{CA}NORD_CA_EOF\n",
            "cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'\n",
            "{TA}NORD_TA_EOF\n",
            "cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'\n",
            "{USERNAME}\n",
            "{PASSWORD}\n",
            "NORD_AUTH_EOF\n",
            "chmod 600 /etc/openvpn/nordvpn.auth\n",
            "\n",
            "uci -q delete openvpn.nordvpn\n",
            "uci set openvpn.nordvpn=openvpn\n",
            "uci set openvpn.nordvpn.enabled='1'\n",
            "uci set openvpn.nordvpn.client='1'\n",
            "uci set openvpn.nordvpn.dev='tun'\n",
            "uci set openvpn.nordvpn.proto='{PROTO}'\n",
            "{REMOTES}\n",
            "uci set openvpn.nordvpn.resolv_retry='infinite'\n",
            "uci set openvpn.nordvpn.nobind='1'\n",
            "uci set openvpn.nordvpn.persist_key='1'\n",
            "uci set openvpn.nordvpn.persist_tun='1'\n",
            "uci set openvpn.nordvpn.ca='/etc/openvpn/nordvpn.ca'\n",
            "uci set openvpn.nordvpn.auth_user_pass='/etc/openvpn/nordvpn.auth'\n",
            "uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'\n",
            "uci set openvpn.nordvpn.key_direction='1'\n",
            "uci set openvpn.nordvpn.verify_x509_name='{HOSTNAME} name'\n",
            "uci set openvpn.nordvpn.remote_cert_tls='server'\n",
            "uci set openvpn.nordvpn.cipher='{CIPHER}'\n",
            "uci set openvpn.nordvpn.data_ciphers='AES-256-GCM:AES-256-CBC'\n",
            "uci set openvpn.nordvpn.auth='SHA512'\n",
            "uci set openvpn.nordvpn.comp_lzo='no'\n",
            "uci set openvpn.nordvpn.mssfix='1450'\n",
            "uci set openvpn.nordvpn.ping='15'\n",
            "uci set openvpn.nordvpn.ping_restart='0'\n",
            "uci set openvpn.nordvpn.verb='3'\n",
            "uci set openvpn.nordvpn.pull='1'\n",
            "uci commit openvpn\n",
            "\n",
            "# Bring tun0 up and attach the vpn zone to it\n",
            "uci -q del_list firewall.vpn_zone.network='wg0'\n",
            "uci -q add_list firewall.vpn_zone.network='tun0'\n",
            "/etc/init.d/openvpn restart || /etc/init.d/openvpn start\n",
        ),
        CA = NORDVPN_OPENVPN_CA,
        TA = NORDVPN_OPENVPN_TLS_AUTH,
        USERNAME = nv.username,
        PASSWORD = nv.password,
        PROTO = nv.proto,
        REMOTES = remotes,
        HOSTNAME = nv.hostname,
        CIPHER = nv.cipher,
    );
    let payload = format!(
        "cat > /tmp/nordvpn_openvpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/nordvpn_openvpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "openvpn-openssl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition + the 45s tun-address verify TAIL
    push_vpn_shared_ops(
        &mut ops,
        "tun0",
        &["103.86.96.100", "103.86.99.100"],
        nv.kill_switch,
        nv.allow_management,
        "i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    // honest outcome: verified requires tun0 to hold an address
    let verification = vec![
        VerificationCheck {
            description: "openvpn instance enabled".into(),
            command: "uci -q get openvpn.nordvpn.enabled".into(),
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
        profile_id: "vpn-nordvpn-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
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
        warnings: Vec::new(),
    })
}

fn plan_mptcp_bonding(model: &DeviceModel, mp: &MptcpBondingProfile) -> Result<Plan, Unsupported> {
    mp.validate()?;
    // 1.x ships a legacy `apk add curl || opkg …` one-liner here —
    // package delivery, excluded from golden comparison; the 2.x port
    // uses the #421 apk-aware EnsurePackage instead (with the
    // offline-installed guard the raw one-liner lacks).
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell {
            command: format!(
                "curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \
                 --server-ipv4 {} --server-port {} --uuid {}",
                mp.server_ipv4, mp.server_port, mp.uuid
            ),
        },
        PlanOp::Shell {
            command: "echo \"BSBF installed. Verify: bsbf-bonding --status\"".into(),
        },
        PlanOp::Shell {
            command: "echo \"Monitor: bsbf-netspeed\"".into(),
        },
        PlanOp::Shell {
            command: "echo \"Uninstall: bsbf-bonding --uninstall\"".into(),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "BSBF client installed".into(),
            command: "command -v bsbf-bonding >/dev/null 2>&1 && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            // upstream MPTCP ABI on 25.12+/SNAPSHOT is the sysctl tree,
            // not the legacy /proc/net/mptcp_net dir the 1.x docstring
            // names — which would false-fail good devices (Codex #600 P2,
            // kernel doc: docs.kernel.org/networking/mptcp-sysctl.html).
            // Reading "1" proves support AND enabled in one probe.
            description: "MPTCP kernel enabled (25.12+/SNAPSHOT prerequisite)".into(),
            command: "cat /proc/sys/net/mptcp/enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            // CVE-2026-98432 (CVSS 9.8): IPv4-TCP-handshake UAF with
            // the proven zero-click-root path against MPTCP listeners;
            // fixed at kernel 6.12.113 (6.6.159 on the 6.6 series).
            // MPTCP-bearing 25.12 kernels are 6.12.x — refuse to call
            // an apply healthy on an unpatched kernel.
            description: "kernel patched for CVE-2026-98432 (>= 6.12.113)".into(),
            command: "K=$(uname -r); awk -v k=\"$K\" 'BEGIN{split(k,a,\"[-.]\"); \
                      if (a[1]>6 || (a[1]==6 && (a[2]>12 || (a[2]==12 && a[3]>=113)))) exit 0; \
                      exit 1}' && echo patched || echo VULNERABLE"
                .into(),
            expect_contains: "patched".into(),
        },
    ];
    Ok(Plan {
        profile_id: "mptcp-bonding".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

fn plan_vpn_openvpn(model: &DeviceModel, vo: &VpnOpenvpnProfile) -> Result<Plan, Unsupported> {
    vo.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = ["openvpn-openssl", "luci-app-openvpn"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    // 1.x setup script, byte-verbatim: the quoted heredoc makes the
    // config literal (validate() gates the OVPNEOF delimiter);
    // credentials ride UCI overrides — the init script's contract for
    // external-config instances (Codex #603 P1)
    let mut setup = String::new();
    setup.push_str("# Write OpenVPN config\n");
    setup.push_str("mkdir -p /etc/openvpn\n");
    setup.push_str("cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'\n");
    setup.push_str(&vo.ovpn_config);
    setup.push_str("\nOVPNEOF\n");
    ops.push(PlanOp::Shell { command: setup });
    ops.push(PlanOp::CleanupUciSections {
        config: "openvpn".into(),
        pattern: "vpn_client=config-openvpn".into(),
    });
    // the 1.x pattern `config=openvpn` matched NOTHING (uci show
    // renders the declaration with a hyphen; values are quoted) — dead
    // cleanup, so stale options like previous credentials survived
    // re-applies. The matching cleanup deletes the section; the
    // recreate below then rebuilds it option-clean (Codex #603 P2).
    ops.push(PlanOp::CleanupUciSections {
        config: "openvpn".into(),
        pattern: "vpn_client=openvpn".into(),
    });
    // section type `openvpn` (Codex #603 P1): the init script starts
    // instances via `config_foreach start_uci_instance 'openvpn'` —
    // the 1.x type `config-openvpn` was never started at all
    ops.push(PlanOp::Shell {
        command: "uci set openvpn.vpn_client=openvpn".into(),
    });
    let mut client_opts = vec![
        (
            "config".to_string(),
            literal("/etc/openvpn/vpn-client.ovpn".into()),
        ),
        ("enabled".to_string(), literal("1".into())),
    ];
    if !vo.username.is_empty() && !vo.password.is_empty() {
        client_opts.push(("username".to_string(), literal(vo.username.clone())));
        client_opts.push(("password".to_string(), literal(vo.password.clone())));
    }
    ops.push(PlanOp::SetUciOptions {
        config: "openvpn".into(),
        section: "vpn_client".into(),
        options: client_opts,
    });
    ops.push(PlanOp::CommitUci {
        config: "openvpn".into(),
    });
    ops.push(PlanOp::CleanupUciSections {
        config: "network".into(),
        pattern: "proto='openvpn'".into(),
    });
    // proto='openvpn' is NOT a netifd protocol (no handler ships) —
    // the 1.x vpn_if never came up and the zone referencing it never
    // matched. Unmanaged interface on the actual tunnel device, the
    // ansible/roles/pia_openvpn pattern (Codex #603 P1 finding 3).
    ops.push(PlanOp::CleanupUciSections {
        config: "network".into(),
        pattern: "vpn_if=interface".into(),
    });
    ops.push(PlanOp::Shell {
        command: "uci set network.vpn_if=interface".into(),
    });
    ops.push(PlanOp::SetUciOptions {
        config: "network".into(),
        section: "vpn_if".into(),
        options: vec![
            ("proto".to_string(), literal("none".into())),
            ("device".to_string(), literal("tun0".into())),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    // shared firewall block (base.py build_firewall_ops, iface=vpn_if,
    // management on, kill switch per profile)
    for pattern in [
        "name='vpn'",
        "dest='vpn'",
        "name='KillSwitch-Reject-NonVPN'",
        "name='Allow-VPN-Management'",
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
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
            ("network".into(), literal("vpn_if".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
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
    if vo.kill_switch {
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
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::Service {
        name: "openvpn".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    // fail-open tail (base.py build_verify_ops, kind=openvpn): the
    // commits/restarts are idempotent; the 45s tun-check auto-removes
    // the kill switch when the tunnel never comes up — the pairing
    // the 1.x preset forgot (fixed with this port)
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
    if vo.kill_switch {
        ops.push(PlanOp::Shell {
            command: "i=0; while [ $i -lt 45 ]; do \
                      if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then \
                      echo 'VPN: tun interface verified'; exit 0; \
                      fi; sleep 1; i=$((i+1)); \
                      done; \
                      echo 'VPN: tun interface failed — removing kill switch to restore WAN'; \
                      uci delete firewall.vpn_killswitch; \
                      uci commit firewall; \
                      fw4 restart"
                .into(),
        });
    }
    let verification = vec![
        VerificationCheck {
            description: "openvpn service section enabled".into(),
            command: "uci -q get openvpn.vpn_client.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "tun interface carrying an address".into(),
            command: "ip -4 addr show dev tun0 2>/dev/null | grep -q inet && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

fn plan_tollgate(model: &DeviceModel, tg: &TollgateProfile) -> Result<Plan, Unsupported> {
    tg.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    // TLS-backend guard (plan_ssl's, Codex #601 P2): the libustream
    // variants all own libustream-ssl.so — unconditionally installing
    // wolfssl next to an existing backend is a file-clash abort under
    // `set -e` before the portal is configured. Install only when NO
    // provider is present (the 1.x packages list entry stays an
    // image-build choice); excluded from golden parity by the
    // established ssl-guard comparator filter.
    let mut ops: Vec<PlanOp> = vec![PlanOp::Shell {
        command: concat!(
            "if ! (opkg list-installed 2>/dev/null || apk info 2>/dev/null) ",
            "| grep -q '^libustream-'; then ",
            "if command -v apk >/dev/null 2>&1; then ",
            "apk add libustream-wolfssl || { apk update && apk add libustream-wolfssl; }; ",
            "else opkg update && opkg install libustream-wolfssl; fi; fi",
        )
        .into(),
    }];
    ops.extend(
        ["nodogsplash", "ca-bundle", "ca-certificates"]
            .iter()
            .map(|name| PlanOp::EnsurePackage {
                name: (*name).into(),
            }),
    );
    ops.push(PlanOp::SetUciOptions {
        config: "nodogsplash".into(),
        section: "@nodogsplash[0]".into(),
        options: vec![("enabled".into(), literal("1".into()))],
    });
    let mut branding = Vec::new();
    if !tg.gateway_name.is_empty() {
        branding.push(("gatewayname".to_string(), tg.gateway_name.clone()));
    }
    if !tg.gateway_domain.is_empty() {
        branding.push(("gatewaydomainname".to_string(), tg.gateway_domain.clone()));
    }
    if !tg.clientid.is_empty() {
        branding.push(("clientid".to_string(), tg.clientid.clone()));
    }
    if !branding.is_empty() {
        ops.push(PlanOp::SetUciOptions {
            config: "nodogsplash".into(),
            section: "@nodogsplash[0]".into(),
            options: branding.into_iter().map(|(k, v)| (k, literal(v))).collect(),
        });
    }
    // guarded del_list before each add_list — idempotent re-configure
    // (1.x plain-appended duplicates; fixed Python-side with this port)
    let mut rules = vec!["allow tcp port 2121", "allow tcp port 2050"];
    if tg.allow_lan_ssh {
        rules.push("allow tcp port 22");
    }
    for rule in rules {
        ops.push(PlanOp::Shell {
            command: format!(
                "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='{rule}' \
                 2>/dev/null || true"
            ),
        });
        ops.push(PlanOp::UciAddList {
            config: "nodogsplash".into(),
            section: "@nodogsplash[0]".into(),
            option: "users_to_router".into(),
            value: rule.into(),
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "nodogsplash".into(),
    });
    ops.push(PlanOp::Service {
        name: "nodogsplash".into(),
        action: ServiceAction::Enable,
    });
    ops.push(PlanOp::Service {
        name: "nodogsplash".into(),
        action: ServiceAction::Restart,
    });
    if tg.install_hotplug {
        // 1.x _HOTPLUG_SCRIPT, byte-verbatim (the \u2014 in the logger
        // line is a LITERAL escape sequence in the 1.x source, kept)
        let iface = &tg.hotplug_interface;
        ops.push(PlanOp::Shell {
            command: format!(
                "mkdir -p /etc/hotplug.d/iface && \
                 printf '%s' '#!/bin/sh\n\
                 [ \"$ACTION\" = \"ifup\" ] || exit 0\n\
                 [ \"$INTERFACE\" = \"{iface}\" ] || exit 0\n\
                 logger -t tollgate-hotplug \"{iface} up \\u2014 restarting tollgate\"\n\
                 /etc/init.d/tollgate-wrt restart &\n\
                 ' > /etc/hotplug.d/iface/95-tollgate-restart && \
                 chmod +x /etc/hotplug.d/iface/95-tollgate-restart"
            ),
        });
    }
    if !tg.mint_url.is_empty() || !tg.lightning_address.is_empty() || tg.price_per_minute != 1 {
        ops.push(PlanOp::Shell {
            command: "touch /etc/config/tollgate".into(),
        });
        let mut values: Vec<(String, UciValue)> = Vec::new();
        if !tg.mint_url.is_empty() {
            values.push(("mint_url".into(), literal(tg.mint_url.clone())));
        }
        if !tg.lightning_address.is_empty() {
            values.push((
                "lightning_address".into(),
                literal(tg.lightning_address.clone()),
            ));
        }
        if tg.price_per_minute != 1 {
            values.push((
                "price_per_minute".into(),
                literal(tg.price_per_minute.to_string()),
            ));
        }
        // named section — 1.x's anonymous `uci add` accumulated one
        // section per re-run (fixed Python-side with this port)
        ops.push(PlanOp::Shell {
            command: "uci set tollgate.payment=tollgate".into(),
        });
        ops.push(PlanOp::SetUciOptions {
            config: "tollgate".into(),
            section: "payment".into(),
            options: values,
        });
        ops.push(PlanOp::CommitUci {
            config: "tollgate".into(),
        });
    }
    if let Some((price, _origin)) = tg.derived_price_checked()? {
        ops.push(PlanOp::Shell {
            command: format!(
                "if [ -f /etc/tollgate/config.json ]; then \
                 SS=$(sed -n 's/.*\"step_size\":[ ]*\\([0-9][0-9]*\\).*/\\1/p' \
                 /etc/tollgate/config.json | head -1); \
                 [ -n \"$SS\" ] || SS=1048576; \
                 P=$(( ( {price} * SS + 1048575 ) / 1048576 )); \
                 sed -i 's/\"price_per_step\":[ ]*[0-9]*/\"price_per_step\": '\"$P\"'/g' \
                 /etc/tollgate/config.json \
                 && /etc/init.d/tollgate-wrt restart 2>/dev/null \
                 && echo \"tollgate: price_per_step=$P applied (step_size=$SS bytes; {price} sat/MiB)\" \
                 || echo \"tollgate: price patch FAILED on existing config.json\"; \
                 else echo \"tollgate: /etc/tollgate/config.json absent (ipk not installed yet) \
                 — re-run configure after deploy_tollgate_post_flash\"; fi"
            ),
        });
    }
    let mut verification = vec![
        VerificationCheck {
            description: "nodogsplash enabled".into(),
            command: "uci -q get nodogsplash.@nodogsplash[0].enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "portal service enabled at boot".into(),
            command: "/etc/init.d/nodogsplash enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    if !tg.mint_url.is_empty() {
        verification.push(VerificationCheck {
            description: "payment mint url persisted".into(),
            command: "uci -q get tollgate.payment.mint_url".into(),
            expect_contains: tg.mint_url.clone(),
        });
    }
    Ok(Plan {
        profile_id: "tollgate".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

fn plan_tollgate_security(
    model: &DeviceModel,
    _ts: &TollgateSecurityProfile,
) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let ranges = [
        ("10", "10.0.0.0/8"),
        ("172", "172.16.0.0/12"),
        ("192", "192.168.0.0/16"),
        ("LL", "169.254.0.0/16"),
    ];
    let mut ops: Vec<PlanOp> = Vec::new();
    for (suffix, cidr) in ranges {
        let name = format!("Block-LAN-To-RFC1918-{suffix}");
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: name.clone(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal(name.clone())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("dest_ip".into(), literal(cidr.into())),
                ("proto".into(), literal("all".into())),
                ("family".into(), literal("ipv4".into())),
                ("target".into(), literal("DROP".into())),
            ],
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    // Codex #601 P1: committed UCI alone leaves the RUNNING firewall
    // open until some later reload — activate before apply reports
    // success, and verify the LIVE ruleset (below), not just UCI.
    ops.push(PlanOp::Service {
        name: "firewall".into(),
        action: ServiceAction::Restart,
    });
    // client isolation over DISCOVERED wifi-iface sections (Codex #601
    // P2 round 2): hardcoded default_radio0/1 aborted mid-apply on
    // single-radio devices under `set -e` — firewall already
    // activated, isolation never applied. Factory section names are
    // not a guarantee; `done; true` guards zero-iface devices.
    ops.push(PlanOp::Shell {
        command: "for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' \
                  | cut -d. -f2 | cut -d= -f1); do \
                  uci set wireless.$_s.isolate='1'; done; true"
            .into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "wireless".into(),
    });
    ops.push(PlanOp::Shell {
        command: "wifi reload".into(),
    });
    let verification = vec![
        VerificationCheck {
            description: "ISP-LAN block rule persisted".into(),
            command: "uci -q get firewall.Block-LAN-To-RFC1918-192.target".into(),
            expect_contains: "DROP".into(),
        },
        VerificationCheck {
            description: "client isolation set on at least one wifi-iface".into(),
            command: "uci show wireless 2>/dev/null | grep -q \"isolate='1'\" && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "block rule LIVE in the fw4 ruleset (effective \
                          protection, not just staged UCI)"
                .into(),
            // whole TABLE, not the base forward chain: fw4 emits
            // src='lan' rules into the forward_lan zone chain, and
            // `list chain` does not recurse into jump targets (Codex
            // #601 P1 round 2)
            command: "nft list table inet fw4 2>/dev/null \
                      | grep -q Block-LAN-To-RFC1918-192 && echo yes"
                .into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "tollgate-security".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
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
    let poll_script = substitute_tokens(
        NODNS_POLL_SCRIPT_TEMPLATE,
        &[
            ("__URL__", nd.api_url.as_str()),
            ("__ZONE__", nd.zone.as_str()),
            ("__POLL_INTERVAL__", &nd.poll_interval.to_string()),
        ],
    );
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        // Radio discovery + HARD GATE before any section is written
        // (#454): a band the device lacks aborts with ZERO partial
        // config. The loop's uci get is set -e-safe (missing radios
        // fail their get) — the old shape committed network/dhcp/
        // firewall first and only then probed.
        PlanOp::Shell {
            command: format!(
                "_radio=\"\"; for _r in radio0 radio1 radio2 radio3; do \
                 _b=$(uci get wireless.${{_r}}.band 2>/dev/null || true); \
                 if [ \"$_b\" = \"{band_short}\" ]; then _radio=$_r; break; fi; done; \
                 if [ -z \"$_radio\" ]; then \
                 echo 'guest-wifi: no {band_short} radio found — aborting before any config changes' >&2; \
                 exit 1; fi"
            ),
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
    // (idempotent — overwrites on reconfigure). $_radio is guaranteed by
    // the hard gate before the first commit (#454) — the VAP sets are
    // unconditional; the loop itself now lives up front with the gate.
    let mut radio_line = format!(
        "uci set wireless.guest_ap=wifi-iface; \
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
         uci set wireless.guest_ap.isolate={isolated}"
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
        warnings: Vec::new(),
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
    // advisories render as comments only — never commands (golden
    // comparator filters comments, so parity is unaffected)
    for warning in &plan.warnings {
        script.push_str(&format!("# WARNING: {warning}\n"));
    }
    if !plan.warnings.is_empty() {
        script.push('\n');
    }

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
        warnings: Vec::new(),
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
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"25.12.6\"}},\
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
    fn openwrt_24x_models_get_deprecation_warning_not_refusal() {
        let v24 = model_with_version("24.10.2");
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &v24,
            &Profile::Sqm(test_sqm_defaults()),
        )
        .expect("24.x plans — policy is warn, not refuse");
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].contains("24.x"));
        assert!(plan.warnings[0].contains("CVE-2026-98432"));
        // and the warning renders as a comment, never a command
        let script = render_shell(&plan);
        assert!(script.contains("# WARNING: OpenWrt 24.x"));
        let command = script
            .lines()
            .find(|l| l.trim_start().starts_with("WARNING") && !l.starts_with('#'));
        assert!(
            command.is_none(),
            "warning must render as a comment line only"
        );
        // 25.12 models: no warning
        let v25 = model_with_version("25.12.6");
        let clean = plan_profile(
            &DeviceState::OpenWrt,
            &v25,
            &Profile::Sqm(test_sqm_defaults()),
        )
        .expect("plans");
        assert!(clean.warnings.is_empty());
    }

    #[test]
    fn live_release_overrides_stale_model_version() {
        let mp = || {
            Profile::MptcpBonding(MptcpBondingProfile {
                server_ipv4: "203.0.113.7".into(),
                server_port: 16384,
                uuid: "u".into(),
            })
        };
        let v24_model = model_with_version("24.10.2");
        // device sysupgraded under a stale `24.10.2` model: the
        // authenticated 25.12.6 release wins — plans, no warning
        let plan =
            plan_profile_for_device(&DeviceState::OpenWrt, &v24_model, &mp(), Some("25.12.6"))
                .expect("live release wins over the stale model claim");
        assert!(plan.warnings.is_empty());
        // and the reverse: a model claiming 25.12 on a device actually
        // running 24.10 is judged by reality — refused + (via the
        // model path) would warn
        assert!(matches!(
            plan_profile_for_device(
                &DeviceState::OpenWrt,
                &model_with_version("25.12.6"),
                &mp(),
                Some("24.10.2")
            ),
            Err(Unsupported::OpenWrtTooOld { .. })
        ));
        // unparseable live release falls back to the model claim
        assert!(
            plan_profile_for_device(
                &DeviceState::OpenWrt,
                &model_with_version("25.12.6"),
                &mp(),
                Some("local-build-2026")
            )
            .is_ok()
        );
        // None = offline planning, model claim governs
        assert!(matches!(
            plan_profile_for_device(&DeviceState::OpenWrt, &v24_model, &mp(), None),
            Err(Unsupported::OpenWrtTooOld { .. })
        ));
    }

    #[test]
    fn mptcp_bonding_requires_25_12_floor() {
        // 24.10 model: hard refusal with both versions in the error
        let v2410 = model_with_version("24.10.2");
        let refused = plan_profile(
            &DeviceState::OpenWrt,
            &v2410,
            &Profile::MptcpBonding(MptcpBondingProfile {
                server_ipv4: "203.0.113.7".into(),
                server_port: 16384,
                uuid: "0f0e0d0c-0b0a-4909-8807-060504030201".into(),
            }),
        );
        match refused {
            Err(Unsupported::OpenWrtTooOld { have, need }) => {
                assert_eq!((have.as_str(), need.as_str()), ("24.10.2", "25.12"));
            }
            other => panic!("expected OpenWrtTooOld, got {other:?}"),
        }
        // 25.0-era minor below floor also refuses; 25.12+ and bare `25`
        // (minor unknown → cannot judge) pass
        assert!(matches!(
            plan_profile(
                &DeviceState::OpenWrt,
                &model_with_version("25.6.1"),
                &Profile::MptcpBonding(MptcpBondingProfile {
                    server_ipv4: "203.0.113.7".into(),
                    server_port: 16384,
                    uuid: "u".into(),
                })
            ),
            Err(Unsupported::OpenWrtTooOld { .. })
        ));
        for ok_version in ["25.12.6", "25", "snapshot"] {
            assert!(
                plan_profile(
                    &DeviceState::OpenWrt,
                    &model_with_version(ok_version),
                    &Profile::MptcpBonding(MptcpBondingProfile {
                        server_ipv4: "203.0.113.7".into(),
                        server_port: 16384,
                        uuid: "u".into(),
                    })
                )
                .is_ok(),
                "{ok_version} must plan"
            );
        }
    }

    #[test]
    fn mptcp_verification_includes_cve_2026_98432_kernel_floor() {
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model_with_capabilities(None),
            &Profile::MptcpBonding(MptcpBondingProfile {
                server_ipv4: "203.0.113.7".into(),
                server_port: 16384,
                uuid: "u".into(),
            }),
        )
        .expect("plans");
        let cve = plan
            .verification
            .iter()
            .find(|c| c.description.contains("CVE-2026-98432"))
            .expect("CVE kernel-floor check");
        assert!(cve.description.contains("6.12.113"));
        assert!(cve.command.contains("uname -r"));
        // the encoded floor: awk major>6 || (6, >12 || 12 && >=113)
        assert!(cve.command.contains("a[2]==12 && a[3]>=113"));
        assert_eq!(cve.expect_contains, "patched");
    }

    fn model_with_version(version: &str) -> DeviceModel {
        let json = format!(
            "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"{version}\"}},\
              \"mac_oui\":[]}}"
        );
        serde_json::from_str(&json).expect("fixture model parses")
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

    // ---- cashu-vpn-client port (1.x `cashu_vpn_client.py`, experimental) ----

    fn cashu_vpn() -> CashuVpnClientProfile {
        CashuVpnClientProfile {
            peer_public_key: "EXITKEY".into(),
            peer_ip: "10.66.42.2/32".into(),
            server_host: "vpn.example.com".into(),
            ..CashuVpnClientProfile::default()
        }
    }

    #[test]
    fn cashu_vpn_param_bounds_match_1x_required_gates() {
        assert!(cashu_vpn().validate().is_ok());
        assert!(matches!(
            CashuVpnClientProfile {
                peer_public_key: String::new(),
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            CashuVpnClientProfile {
                peer_ip: "10.66.42.2".into(),
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            CashuVpnClientProfile {
                peer_ip: String::new(),
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            CashuVpnClientProfile {
                server_host: String::new(),
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            CashuVpnClientProfile {
                server_host: "vpn; rm -rf /".into(),
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            CashuVpnClientProfile {
                server_port: 0,
                ..cashu_vpn()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn cashu_vpn_requires_ethernet_capability() {
        let missing = model_with_capabilities(Some(vec!["wifi".into()]));
        let refusal = plan_profile(
            &DeviceState::OpenWrt,
            &missing,
            &Profile::CashuVpnClient(cashu_vpn()),
        );
        assert!(matches!(
            refusal,
            Err(Unsupported::MissingCapability { .. })
        ));
        let plan = plan_for(Profile::CashuVpnClient(cashu_vpn()));
        assert_eq!(plan.profile_id, "cashu-vpn-client");
    }

    #[test]
    fn cashu_vpn_render_matches_1x_shape() {
        let script = render_shell(&plan_for(Profile::CashuVpnClient(cashu_vpn())));
        assert!(script.contains("kmod-wireguard"));
        assert!(script.contains("wireguard-tools"));
        assert!(script.contains("uci set network.wg0.addresses='10.66.42.2/32'"));
        assert!(script.contains("uci add_list network.wg0.dns='1.1.1.1'"));
        assert!(script.contains("uci set network.wg0_peer.public_key='EXITKEY'"));
        assert!(script.contains("uci set network.wg0_peer.endpoint_host='vpn.example.com'"));
        assert!(script.contains("uci set firewall.cashu_vpn_zone.name='vpn'"));
        assert!(script.contains("uci set firewall.cashu_vpn_fwd.dest='vpn'"));
        assert!(script.contains("cashu_vpn_killswitch.name='KillSwitch-Reject-NonVPN'"));
        assert!(script.contains("uci delete firewall.cashu_vpn_killswitch"));
        assert!(script.contains(
            "echo 'Cashu VPN client configured: vpn.example.com:51820 (peer_ip=10.66.42.2/32)'"
        ));
    }

    #[test]
    fn cashu_vpn_kill_switch_and_dns_branches() {
        let off = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
            kill_switch: false,
            ..cashu_vpn()
        })));
        assert!(!off.contains("cashu_vpn_killswitch"));
        assert!(!off.contains("wg show wg0"));

        let multi_dns = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
            dns: "1.1.1.1, 9.9.9.9".into(),
            ..cashu_vpn()
        })));
        assert!(multi_dns.contains("uci add_list network.wg0.dns='1.1.1.1'"));
        assert!(multi_dns.contains("uci add_list network.wg0.dns='9.9.9.9'"));

        let no_dns = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
            dns: String::new(),
            ..cashu_vpn()
        })));
        assert!(!no_dns.contains("uci add_list"));
    }

    #[test]
    fn cashu_vpn_unconfirmed_state_refused() {
        let model = model_with_capabilities(Some(vec!["ethernet".into()]));
        assert_eq!(
            plan_profile(
                &DeviceState::SshOnly,
                &model,
                &Profile::CashuVpnClient(cashu_vpn())
            ),
            Err(Unsupported::UnconfirmedDeviceState(DeviceState::SshOnly))
        );
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
    fn vpn_pia_shape_gates_and_branches_match_1x() {
        let base = VpnPiaProfile {
            username: "p1234567".into(),
            password: "testpass".into(),
            region: "czech".into(),
            upstream_gateway: "192.168.1.1".into(),
            ..VpnPiaProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnPia(base.clone())));
        // curl IS ensured — the script's first act is `curl -u` auth
        // (hardening audit; the surfshark #604-P2 class)
        assert!(script.contains("# install package curl"));
        // one heredoc runtime-API payload: keypair on device, token
        // exchange, addKey, abort-before-cleanup gates
        assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
        assert!(script.contains("wg genkey > /tmp/vpn_private.key"));
        assert!(script.contains("curl -fs -m 15 -u 'p1234567:testpass'"));
        assert!(script.contains("https://czech.privacy.network:1337/addKey"));
        assert!(script.contains("aborting before wg0 cleanup"));
        // creds with a single quote survive sh-quoted (1.x parity)
        let quoted = render_shell(&plan_for(Profile::VpnPia(VpnPiaProfile {
            password: "p$a\"b'c".into(),
            ..base.clone()
        })));
        assert!(
            quoted.contains("-u 'p1234567:p$a\"b'\\''c'"),
            "sh_quote parity"
        );

        // gates: creds required + no control chars, region alnum,
        // gateway IPv4, iface charset
        for hostile in [
            VpnPiaProfile {
                username: String::new(),
                ..base.clone()
            },
            VpnPiaProfile {
                password: "l1\nl2".into(),
                ..base.clone()
            },
            VpnPiaProfile {
                region: "czech; poweroff".into(),
                ..base.clone()
            },
            VpnPiaProfile {
                region: "prague-1".into(),
                ..base.clone()
            },
            VpnPiaProfile {
                upstream_gateway: "not-an-ip".into(),
                ..base.clone()
            },
            VpnPiaProfile {
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
    fn vpn_nordvpn_openvpn_shape_gates_and_branches_match_1x() {
        let base = VpnNordvpnOpenvpnProfile {
            username: "svcuser1234".into(),
            password: "svcpass5678abcd".into(),
            station: "193.29.107.10".into(),
            hostname: "de500.nordvpn.com".into(),
            ..VpnNordvpnOpenvpnProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnNordvpnOpenvpn(base.clone())));
        // one heredoc payload; CA + tls-auth + credentials as static files
        assert!(script.contains("cat > /tmp/nordvpn_openvpn_setup.sh << 'VPN_SETUP_EOF'"));
        assert!(script.contains("cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'"));
        assert!(script.contains(
            "cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'\nsvcuser1234\nsvcpass5678abcd"
        ));
        assert!(script.contains("chmod 600 /etc/openvpn/nordvpn.auth"));
        // template-faithful: multi-port remotes + x509 CN pin from the
        // SAME server object + tls-auth direction
        assert!(script.contains("uci add_list openvpn.nordvpn.remote='193.29.107.10 1234'"));
        assert!(
            script.contains("uci set openvpn.nordvpn.verify_x509_name='de500.nordvpn.com name'")
        );
        assert!(script.contains("uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'"));
        assert!(script.contains("uci set openvpn.nordvpn.key_direction='1'"));
        assert!(script.contains("uci set openvpn.nordvpn.cipher='AES-256-CBC'"));
        assert!(script.contains("uci set openvpn.nordvpn.proto='udp'"));

        // tcp variant flips the proto only
        let tcp = render_shell(&plan_for(Profile::VpnNordvpnOpenvpn(
            VpnNordvpnOpenvpnProfile {
                proto: "tcp".into(),
                ..base.clone()
            },
        )));
        assert!(tcp.contains("uci set openvpn.nordvpn.proto='tcp'"));

        // gates: creds required + no control chars + no delimiters,
        // station IPv4, hostname charset, proto choice, cipher charset
        for hostile in [
            VpnNordvpnOpenvpnProfile {
                username: String::new(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                password: "l1\nl2".into(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                username: "NORD_AUTH_EOF".into(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                station: "de500.nordvpn.com".into(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                hostname: "host; poweroff".into(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                proto: "icmp".into(),
                ..base.clone()
            },
            VpnNordvpnOpenvpnProfile {
                cipher: "AES-256-CBC'; reboot".into(),
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
        // the sed captures need SINGLE backslashes at render time —
        // doubled ones match nothing and the discovery always times
        // out (Codex #526 P2; the source template's \\ must not leak)
        assert!(discover.contains("sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p'"));
        assert!(!discover.contains("\\\\("));

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
    fn tollgate_shape_branches_and_gates_match_1x() {
        let tg = TollgateProfile {
            gateway_name: "net4sats".into(),
            gateway_domain: "net4sats.lan".into(),
            allow_lan_ssh: true,
            mint_url: "https://mint.example.com".into(),
            lightning_address: "user@domain.com".into(),
            price_per_minute: 5,
            upstream_usd_per_gb: "0.83".into(),
            markup: "2.0".into(),
            fx_sats_per_usd: 2500,
            ..TollgateProfile::default()
        };
        let script = render_shell(&plan_for(Profile::Tollgate(tg.clone())));
        assert!(script.contains("uci set nodogsplash.@nodogsplash[0].enabled='1'"));
        assert!(script.contains("uci set nodogsplash.@nodogsplash[0].gatewayname='net4sats'"));
        assert!(
            script.contains("uci set nodogsplash.@nodogsplash[0].gatewaydomainname='net4sats.lan'")
        );
        assert!(script.contains("uci set nodogsplash.@nodogsplash[0].clientid='mac'"));
        // idempotency fixes: guarded del_list pairs, named payment section
        for rule in [
            "allow tcp port 2121",
            "allow tcp port 2050",
            "allow tcp port 22",
        ] {
            assert!(script.contains(&format!(
                "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='{rule}' \
                 2>/dev/null || true"
            )));
            assert!(script.contains(&format!(
                "uci add_list nodogsplash.@nodogsplash[0].users_to_router='{rule}'"
            )));
        }
        assert!(!script.contains("uci add tollgate"));
        assert!(script.contains("uci set tollgate.payment=tollgate"));
        assert!(script.contains("uci set tollgate.payment.mint_url='https://mint.example.com'"));
        assert!(script.contains("uci set tollgate.payment.price_per_minute='5'"));
        assert!(script.contains("uci commit tollgate"));
        // hotplug hook: verbatim script body, literal \u2014 escape kept
        assert!(script.contains("[ \"$INTERFACE\" = \"wwan\" ] || exit 0"));
        assert!(
            script.contains("logger -t tollgate-hotplug \"wwan up \\u2014 restarting tollgate\"")
        );
        // fx-derived price: 0.83/1024*2500*2.0 = 4.05 -> ceil 5
        assert!(script.contains("P=$(( ( 5 * SS + 1048575 ) / 1048576 ))"));
        assert!(script.contains("5 sat/MiB"));

        // minimal profile: no payment section, no ssh rule, hotplug on
        let minimal = render_shell(&plan_for(Profile::Tollgate(TollgateProfile::default())));
        assert!(minimal.contains("uci set nodogsplash.@nodogsplash[0].enabled='1'"));
        assert!(!minimal.contains("users_to_router='allow tcp port 22'"));
        assert!(!minimal.contains("tollgate.payment"));
        assert!(minimal.contains("[ \"$INTERFACE\" = \"wwan\" ]"));
        // hotplug off drops the hook entirely
        let no_hotplug = render_shell(&plan_for(Profile::Tollgate(TollgateProfile {
            install_hotplug: false,
            ..TollgateProfile::default()
        })));
        assert!(!no_hotplug.contains("hotplug.d/iface"));
        // explicit price pins the direct path
        let explicit = render_shell(&plan_for(Profile::Tollgate(TollgateProfile {
            price_sats_per_mib: 8,
            ..TollgateProfile::default()
        })));
        assert!(explicit.contains("P=$(( ( 8 * SS + 1048575 ) / 1048576 ))"));

        // gates: runtime injection via hotplug_interface; clientid
        // choice set; pricing bounds + the purity-delta fx requirement
        assert!(matches!(
            TollgateProfile {
                hotplug_interface: "wwan$(reboot)".into(),
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            TollgateProfile {
                clientid: "evil".into(),
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            TollgateProfile {
                markup: "0".into(),
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            TollgateProfile {
                fx_sats_per_usd: 0,
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            TollgateProfile {
                upstream_usd_per_gb: "not-a-number".into(),
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // overflow guard: absurd derived prices are rejected, never
        // wrapped to a zero (free-access) price (Codex #601 P2 round 3)
        assert!(matches!(
            TollgateProfile {
                upstream_usd_per_gb: "1000000000".into(),
                markup: "2".into(),
                fx_sats_per_usd: 2500,
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        // NaN/inf operands are rejected, never laundered through the
        // 1.0 clamp into a 1-sat price (Codex #601 P2 round 4)
        for bad in ["NaN", "inf", "-inf"] {
            assert!(
                matches!(
                    TollgateProfile {
                        markup: bad.into(),
                        ..tg.clone()
                    }
                    .validate(),
                    Err(Unsupported::InvalidParams(_))
                ),
                "markup {bad} must be refused"
            );
        }
        assert!(matches!(
            TollgateProfile {
                upstream_usd_per_gb: "NaN".into(),
                ..tg.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn tollgate_security_shape_matches_1x() {
        let script = render_shell(&plan_for(Profile::TollgateSecurity(
            TollgateSecurityProfile,
        )));
        for (suffix, cidr) in [
            ("10", "10.0.0.0/8"),
            ("172", "172.16.0.0/12"),
            ("192", "192.168.0.0/16"),
            ("LL", "169.254.0.0/16"),
        ] {
            assert!(script.contains(&format!(
                "uci set firewall.Block-LAN-To-RFC1918-{suffix}=rule"
            )));
            assert!(script.contains(&format!(
                "uci set firewall.Block-LAN-To-RFC1918-{suffix}.dest_ip='{cidr}'"
            )));
            assert!(script.contains(&format!(
                "uci set firewall.Block-LAN-To-RFC1918-{suffix}.target='DROP'"
            )));
        }
        assert!(!script.contains("uci add firewall"));
        assert!(script.contains("uci commit firewall"));
        assert!(script.contains("uci commit wireless"));
        assert!(script.contains("/etc/init.d/firewall restart"));
        assert!(script.contains("wifi reload"));
        // isolation targets DISCOVERED wifi-iface sections — no
        // hardcoded factory radio names (single-radio devices abort
        // otherwise, Codex #601 P2 round 2)
        assert!(!script.contains("default_radio0"));
        assert!(!script.contains("default_radio1"));
        assert!(script.contains("uci set wireless.$_s.isolate='1'"));
        assert!(!script.contains("OUTPUT"));
        // the P1 fix verifies EFFECTIVE protection: the live fw4
        // ruleset must carry the block rule, not just staged UCI — and
        // the whole TABLE (fw4 puts src-zone rules in forward_lan)
        let plan = plan_for(Profile::TollgateSecurity(TollgateSecurityProfile));
        let live = plan
            .verification
            .iter()
            .find(|c| c.description.contains("LIVE"))
            .expect("live-ruleset check");
        assert!(live.command.contains("nft list table inet fw4"));
        assert!(!live.command.contains("list chain"));
        assert!(live.command.contains("Block-LAN-To-RFC1918-192"));
        // the libustream TLS backend is presence-guarded (P2), never
        // unconditionally ensured
        let tg_script = render_shell(&plan_for(Profile::Tollgate(TollgateProfile::default())));
        assert!(tg_script.contains("| grep -q '^libustream-'"));
        assert!(!tg_script.contains("# install package libustream-wolfssl"));
        // wifi capability gate (1.x requires_capabilities=["wifi"])
        assert_eq!(
            Profile::TollgateSecurity(TollgateSecurityProfile).requires(),
            &["wifi"]
        );
    }

    #[test]
    fn vpn_node_shape_gates_and_json_match_1x() {
        let vn = VpnNodeProfile {
            nsec: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            endpoint_host: "vpn.example.com".into(),
            ..VpnNodeProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnNode(vn.clone())));
        assert!(script.contains("cat > /etc/vpn-listing.sh << 'SCRIPT'"));
        assert!(script.contains("-k 30402"));
        assert!(script.contains("-d \"vpn-node\""));
        assert!(script.contains("-t \"region=US\""));
        assert!(script.contains("-t \"price=50sat/hour\""));
        assert!(script.contains(
            "-c '{\"type\":\"vpn-service\",\"name\":\"VPN Node\",\
                 \"endpoint\":\"vpn.example.com:51820\""
        ));
        assert!(script.contains("wss://relay.damus.io wss://relay.cashu.email 2>&1"));
        assert!(script.contains(
            "echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > /etc/vpn-node/nsec"
        ));
        assert!(script.contains("chmod 600 /etc/vpn-node/nsec"));

        // gates: the full baked-text surface
        for bad in [
            VpnNodeProfile {
                nsec: "x'; rm -rf /".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                title: "John's VPN".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                content: "say \"hi\"".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                d_tag: "a\"; rm".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                endpoint_host: "a; rm -rf /".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                country: "swe".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                price_amount: 0,
                ..vn.clone()
            },
            VpnNodeProfile {
                price_unit: "century".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                relays: "wss://a;rm".into(),
                ..vn.clone()
            },
            VpnNodeProfile {
                nak_path: "/usr/bin/nak; rm".into(),
                ..vn.clone()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
                "must refuse: {:?}",
                bad
            );
        }
        // token-shaped payloads survive the single-pass substitution
        let tok = render_shell(&plan_for(Profile::VpnNode(VpnNodeProfile {
            d_tag: "a__NSEC__b".into(),
            ..vn.clone()
        })));
        assert!(tok.contains("-d \"a__NSEC__b\""));
    }

    #[test]
    fn vpn_surfshark_shape_and_gates_match_1x() {
        let ss = VpnSurfsharkProfile {
            username: "svcuser".into(),
            password: "svcpass".into(),
            country: "Germany".into(),
            upstream_gateway: "192.168.8.1".into(),
            ..VpnSurfsharkProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnSurfshark(ss.clone())));
        assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
        assert!(script.contains("-d '{\"username\":\"svcuser\",\"password\":\"svcpass\"}')"));
        assert!(script.contains("test(\"Germany\";\"i\")"));
        assert!(script.contains("uci set network.surfshark_server_route.gateway='192.168.8.1'"));
        assert!(script.contains("uci set network.wg0.proto='wireguard'"));
        assert!(script.contains("uci set firewall.vpn_zone.name='vpn'"));
        assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='162.252.172.57'"));
        assert!(script.contains("wg show wg0"));
        assert!(script.contains("sh /tmp/vpn_setup.sh"));
        // no country: first-server branch, no baked filter
        let no_country = render_shell(&plan_for(Profile::VpnSurfshark(VpnSurfsharkProfile {
            country: String::new(),
            ..ss.clone()
        })));
        assert!(no_country.contains("jq -r '.[0]'"));
        assert!(!no_country.contains("country/"));
        // gates: quote/backslash creds, jq-pattern country, non-IP
        // gateway, iface charset
        for bad in [
            VpnSurfsharkProfile {
                username: "x'; rm -rf /; '".into(),
                ..ss.clone()
            },
            VpnSurfsharkProfile {
                password: "a\\b".into(),
                ..ss.clone()
            },
            VpnSurfsharkProfile {
                country: "Ger\"; rm".into(),
                ..ss.clone()
            },
            VpnSurfsharkProfile {
                upstream_gateway: "$(reboot)".into(),
                ..ss.clone()
            },
            VpnSurfsharkProfile {
                upstream_iface: "wwan; rm".into(),
                ..ss.clone()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
                "must refuse: {:?}",
                bad
            );
        }
        // token-shaped credentials survive substitution verbatim
        // (single-pass, values never re-scanned — Codex #604 P2 r5)
        let tok = render_shell(&plan_for(Profile::VpnSurfshark(VpnSurfsharkProfile {
            password: "abc__IFACE__def".into(),
            ..ss.clone()
        })));
        assert!(tok.contains("\"password\":\"abc__IFACE__def\""));
    }

    #[test]
    fn vpn_openvpn_shape_branches_and_gates_match_1x() {
        let vo = VpnOpenvpnProfile {
            ovpn_config: "client\nremote vpn.example.com 1194\nproto udp\nauth-user-pass".into(),
            username: "svcuser".into(),
            password: "svcpass".into(),
            ..VpnOpenvpnProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnOpenvpn(vo.clone())));
        assert!(script.contains("cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'"));
        assert!(script.contains("remote vpn.example.com 1194"));
        // credentials ride UCI overrides (init-script contract, P1 fix)
        assert!(!script.contains("vpn-auth.txt"));
        assert!(script.contains("uci set openvpn.vpn_client=openvpn"));
        assert!(script.contains("uci set openvpn.vpn_client.username='svcuser'"));
        assert!(script.contains("uci set openvpn.vpn_client.password='svcpass'"));
        // unmanaged interface on the real tunnel device — proto='openvpn'
        // is not a netifd protocol (Codex #603 P1 finding 3)
        assert!(script.contains("uci set network.vpn_if.proto='none'"));
        assert!(script.contains("uci set network.vpn_if.device='tun0'"));
        assert!(!script.contains("uci set network.vpn_if.proto='openvpn'"));
        assert!(script.contains("uci set firewall.vpn_zone.network='vpn_if'"));
        assert!(script.contains("uci set firewall.vpn_killswitch.name='KillSwitch-Reject-NonVPN'"));
        // the fail-open pairing the 1.x preset forgot
        assert!(script.contains("ip -4 addr show dev tun0"));
        assert!(
            script
                .contains("echo 'VPN: tun interface failed — removing kill switch to restore WAN'")
        );

        // no creds: no auth file; no kill switch: no killswitch section
        let bare = render_shell(&plan_for(Profile::VpnOpenvpn(VpnOpenvpnProfile {
            ovpn_config: "client".into(),
            kill_switch: false,
            ..VpnOpenvpnProfile::default()
        })));
        assert!(!bare.contains("vpn-auth.txt"));
        assert!(!bare.contains("uci set firewall.vpn_killswitch=rule"));
        assert!(!bare.contains("tun interface failed"));

        // gates: heredoc terminators, credential newlines, proto choice
        assert!(matches!(
            VpnOpenvpnProfile {
                ovpn_config: "client\nOVPNEOF\nreboot".into(),
                ..vo.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            VpnOpenvpnProfile {
                password: "AUTHEOF".into(),
                ..vo.clone()
            }
            .validate(),
            Ok(())
        ));
        assert!(matches!(
            VpnOpenvpnProfile {
                username: "u\nrm -rf /".into(),
                ..vo.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            VpnOpenvpnProfile {
                proto: "udp; reboot".into(),
                ..vo.clone()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }

    #[test]
    fn mptcp_bonding_shape_and_gates_match_1x() {
        let mp = MptcpBondingProfile {
            server_ipv4: "203.0.113.7".into(),
            server_port: 16384,
            uuid: "0f0e0d0c-0b0a-4909-8807-060504030201".into(),
        };
        let script = render_shell(&plan_for(Profile::MptcpBonding(mp.clone())));
        // installer line: values UNQUOTED (1.x bytes); validate() gates
        assert!(script.contains(
            "curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \
             --server-ipv4 203.0.113.7 --server-port 16384 \
             --uuid 0f0e0d0c-0b0a-4909-8807-060504030201"
        ));
        assert!(script.contains("echo \"BSBF installed. Verify: bsbf-bonding --status\""));
        assert!(script.contains("echo \"Monitor: bsbf-netspeed\""));
        assert!(script.contains("echo \"Uninstall: bsbf-bonding --uninstall\""));
        // kernel prerequisite probes the upstream sysctl, never the
        // legacy /proc/net/mptcp_net dir (Codex #600 P2)
        let plan = plan_for(Profile::MptcpBonding(mp.clone()));
        let kernel_check = plan
            .verification
            .iter()
            .find(|c| c.description.contains("MPTCP"))
            .expect("kernel prerequisite check");
        assert!(kernel_check.command.contains("/proc/sys/net/mptcp/enabled"));
        assert_eq!(kernel_check.expect_contains, "1");
        assert!(!kernel_check.command.contains("mptcp_net"));
        // hostname endpoints stay first-class (validate_host parity)
        assert!(
            MptcpBondingProfile {
                server_ipv4: "vps.example.com".into(),
                ..mp.clone()
            }
            .validate()
            .is_ok()
        );

        // injection gates: hostile values never reach the pipe-to-sh line
        for bad in [
            MptcpBondingProfile {
                server_ipv4: "1.2.3.4; rm -rf /".into(),
                ..mp.clone()
            },
            MptcpBondingProfile {
                server_ipv4: "$(reboot)".into(),
                ..mp.clone()
            },
            MptcpBondingProfile {
                server_ipv4: String::new(),
                ..mp.clone()
            },
            MptcpBondingProfile {
                server_port: 0,
                ..mp.clone()
            },
            MptcpBondingProfile {
                uuid: "$(reboot)".into(),
                ..mp.clone()
            },
            MptcpBondingProfile {
                uuid: String::new(),
                ..mp.clone()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
                "must refuse: {:?}",
                bad
            );
        }
    }

    #[test]
    fn vpn_pia_token_shaped_credentials_survive_substitution() {
        // hardening-audit regression: chained `.replace()` rewrote
        // token-shaped payloads inside the quoted creds before the
        // single-pass substitution landed (surfshark #604-P2 class)
        let base = VpnPiaProfile {
            username: "u__IFACE__x".into(),
            password: "p__GATEWAY__y".into(),
            region: "czech".into(),
            upstream_gateway: "192.168.1.1".into(),
            ..VpnPiaProfile::default()
        };
        let script = render_shell(&plan_for(Profile::VpnPia(base)));
        // creds survive verbatim …
        assert!(script.contains("-u 'u__IFACE__x:p__GATEWAY__y'"));
        // … while the real tokens still substituted
        assert!(script.contains("https://czech.privacy.network:1337/addKey"));
        assert!(script.contains("uci set network.pia_server_route.gateway='192.168.1.1'"));
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
