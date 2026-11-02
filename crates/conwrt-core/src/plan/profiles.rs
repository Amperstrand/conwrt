//! `profiles` — split out of the former plan.rs monolith (pure move).
use super::*;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
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

    pub(super) fn validate(&self) -> Result<(), Unsupported> {
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
    pub(super) fn validate(&self) -> Result<(), Unsupported> {
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
pub(super) fn is_ipv4(s: &str) -> bool {
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
pub(super) fn valid_host(s: &str) -> bool {
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

/// Per-AP Nostr identity — port of the 1.x `ap-nostr-id` preset
/// (`scripts/use_cases/ap_nostr_id.py`, untested tier): writes the AP's
/// Nostr secret to `/etc/tollgate/ap-nsec`, the public key to
/// `ap-npub`, and stamps `nas_identifier` on every `wifi-iface` so
/// RADIUS requests self-identify the AP. 1.x auto-generates a keypair
/// when both params are empty (host-side python, secp256k1); the Rust
/// twin deliberately does NOT pull a crypto dependency for that — the
/// boundary mirrors vpn-node's nsec handling: keys are generated
/// host-side (`scripts/generate_nostr_keypair.py`) and passed in.
/// Values land inside single-quoted shell lines → hard charset gate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApNostrIdProfile {
    /// Public key, bech32 `npub1…` (paired with `nsec`).
    pub npub: String,
    /// Secret key, bech32 `nsec1…` (paired with `npub`).
    pub nsec: String,
}

impl ApNostrIdProfile {
    /// 1.x gates (prefix + both-or-neither) plus the shell-safety
    /// charset gate the 1.x printf/uci interpolations lacked: a
    /// quote-bearing npub would close the single-quoted string and run
    /// arbitrary shell on the router.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.npub.is_empty() && self.nsec.is_empty() {
            return Err(Unsupported::InvalidParams(
                "npub and nsec are required (generate host-side with \\
scripts/generate_nostr_keypair.py — the planner does not generate keys)"
                    .into(),
            ));
        }
        if self.npub.is_empty() || self.nsec.is_empty() {
            return Err(Unsupported::InvalidParams(
                "npub and nsec must both be provided or both be empty".into(),
            ));
        }
        for (name, value, prefix) in [("npub", &self.npub, "npub1"), ("nsec", &self.nsec, "nsec1")]
        {
            if !value.starts_with(prefix) {
                return Err(Unsupported::InvalidParams(format!(
                    "{name} must start with '{prefix}'"
                )));
            }
            let body = &value[prefix.len()..];
            if body.is_empty() || !body.chars().all(|c| BECH32_CHARSET.contains(c)) {
                return Err(Unsupported::InvalidParams(format!(
                    "{name} must be bech32 (charset {BECH32_CHARSET:?} after \\
                     the prefix; no quotes or metacharacters)"
                )));
            }
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
    pub(super) fn listing_json(&self) -> String {
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

/// WiFi performance test client (STA side) — port of the 1.x
/// `openperf_client` preset (`scripts/use_cases/openperf_client.py`,
/// 1.x marks it untested). Deploys the STA autostart procd service
/// and points the 2.4GHz STA + HaHalow interfaces at the openperf AP
/// SSID. The Python test files themselves ride
/// `install-openperf.sh` — this plan shapes the service + radio
/// config only. The SSID lands inside single-quoted uci values →
/// charset-gated (the surfshark #604 class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPerfClientProfile {
    /// SSID to scan for (must match the AP's openperf_server).
    pub mgmt_ssid: String,
}

impl Default for OpenPerfClientProfile {
    fn default() -> Self {
        Self {
            mgmt_ssid: "openperf".into(),
        }
    }
}

impl OpenPerfClientProfile {
    /// SSID charset gate: lands inside single-quoted uci values —
    /// a quote or metacharacter injects shell (surfshark #604 class).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let ok = !self.mgmt_ssid.is_empty()
            && !self.mgmt_ssid.contains(['\'', '"', '\\'])
            && !self.mgmt_ssid.chars().any(|c| (c as u32) < 0x20);
        if !ok {
            return Err(Unsupported::InvalidParams(
                "mgmt_ssid must not contain quotes or control characters".into(),
            ));
        }
        Ok(())
    }
}

/// WiFi performance testing server — port of the 1.x `openperf_server`
/// preset (`scripts/use_cases/openperf_server.py`, 1.x marks it
/// untested). Deploys the JSON-RPC server procd service (PORT param)
/// and configures the AP SSID. The Python files ride
/// `install-openperf.sh` — same boundary as the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPerfServerProfile {
    /// Management SSID broadcast on 2.4 GHz for client discovery.
    pub mgmt_ssid: String,
    /// TCP port for the JSON-RPC server (1.x default 7777).
    pub port: u16,
}

impl Default for OpenPerfServerProfile {
    fn default() -> Self {
        Self {
            mgmt_ssid: "openperf".into(),
            port: 7777,
        }
    }
}

impl OpenPerfServerProfile {
    /// SSID charset gate (same surface as the client) + the JSON-RPC
    /// port bound (1-65535; lands unquoted in the procd env line).
    pub fn validate(&self) -> Result<(), Unsupported> {
        let ok = !self.mgmt_ssid.is_empty()
            && !self.mgmt_ssid.contains(['\'', '"', '\\'])
            && !self.mgmt_ssid.chars().any(|c| (c as u32) < 0x20);
        if !ok {
            return Err(Unsupported::InvalidParams(
                "mgmt_ssid must not contain quotes or control characters".into(),
            ));
        }
        if self.port == 0 {
            return Err(Unsupported::InvalidParams("port must be 1-65535".into()));
        }
        Ok(())
    }
}

/// net4sats admin UI + captive portal — port of the 1.x
/// `configurationwizzard` preset (`scripts/use_cases/
/// configurationwizzard.py`). The entire deployment is a HOST-SIDE
/// operation (`deploy_configurationwizzard()`: npm build → SCP →
/// rpcd plugin install → uhttpd config); the device-side configure
/// ops are purely informational comments. The 2.x plan mirrors that
/// boundary exactly — it emits the same comments and performs NO
/// device mutations (the golden comparator filters them to an empty
/// command stream, proving the parity).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigurationWizzardProfile;

/// FIPS mesh networking over Bluetooth RFCOMM — port of the 1.x
/// `fips-bluetooth-rfcomm` preset (`scripts/use_cases/
/// fips_bluetooth_rfcomm.py`, 1.x marks it experimental — tested on
/// ASUS Lyra MAP-AC2200 star topology). Deploys the fips.yaml config
/// (echo-write for BusyBox compatibility), bt-pin, two procd init
/// scripts (bt-agent + fips), and peers.allow in server mode. The
/// FIPS binary itself rides host-side SCP — documented boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsBluetoothRfcommProfile {
    /// RFCOMM role: `server` accepts connections, `client` initiates.
    pub role: String,
    /// RFCOMM channel number (1.x bound 1–30).
    pub channel: u8,
    /// Enable TUN interface for IP-over-mesh.
    pub tun_enabled: bool,
    /// Enable DNS over TUN.
    pub tun_dns: bool,
    /// Enable gateway over TUN.
    pub tun_gateway: bool,
    /// Bluetooth pairing PIN (lands in `echo '{pin}' > file`).
    pub bt_pin: String,
    /// Mesh peers (Noise + transport level).
    pub peers: Vec<FipsPeer>,
}

/// One FIPS mesh peer: npub + Bluetooth MAC (transport + identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsPeer {
    /// Peer Nostr public key (bech32 npub…).
    pub npub: String,
    /// Peer Bluetooth MAC address (XX:XX:XX:XX:XX:XX).
    pub bt_mac: String,
    /// Optional human alias.
    pub alias: String,
}

impl Default for FipsBluetoothRfcommProfile {
    fn default() -> Self {
        Self {
            role: "client".into(),
            channel: 1,
            tun_enabled: true,
            tun_dns: true,
            tun_gateway: true,
            bt_pin: "0000".into(),
            peers: Vec::new(),
        }
    }
}

impl FipsBluetoothRfcommProfile {
    /// Gates: role choice set, channel 1–30, PIN charset (lands in
    /// `echo '{pin}'` — single-quoted), npub/MAC charsets (land in
    /// double-quoted YAML values + single-quote-escaped echo lines).
    pub fn validate(&self) -> Result<(), Unsupported> {
        if !matches!(self.role.as_str(), "server" | "client") {
            return Err(Unsupported::InvalidParams(
                "role must be server or client".into(),
            ));
        }
        if !(1..=30).contains(&self.channel) {
            return Err(Unsupported::InvalidParams("channel must be 1-30".into()));
        }
        let pin_ok = !self.bt_pin.is_empty()
            && !self.bt_pin.contains(['\'', '"', '\\'])
            && !self.bt_pin.chars().any(|c| (c as u32) < 0x20);
        if !pin_ok {
            return Err(Unsupported::InvalidParams(
                "bt_pin must not contain quotes or control characters".into(),
            ));
        }
        for peer in &self.peers {
            let npub_ok = !peer.npub.is_empty()
                && !peer.npub.contains(['\'', '"', '\\'])
                && !peer.npub.chars().any(|c| (c as u32) < 0x20);
            if !npub_ok {
                return Err(Unsupported::InvalidParams(
                    "peer npub must not contain quotes or control characters".into(),
                ));
            }
            let mac_ok = !peer.bt_mac.is_empty()
                && peer
                    .bt_mac
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':');
            if !mac_ok {
                return Err(Unsupported::InvalidParams(
                    "peer bt_mac must be a hex MAC address (XX:XX:XX:XX:XX:XX)".into(),
                ));
            }
            let alias_ok = peer.alias.is_empty()
                || (!peer.alias.contains(['\'', '"', '\\'])
                    && !peer.alias.chars().any(|c| (c as u32) < 0x20));
            if !alias_ok {
                return Err(Unsupported::InvalidParams(
                    "peer alias must not contain quotes or control characters".into(),
                ));
            }
        }
        Ok(())
    }

    /// The fips.yaml content (1.x `_build_yaml_parts` parity).
    pub(super) fn yaml_config(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        lines.push("node:".into());
        lines.push("  identity:".into());
        lines.push("    persistent: true".into());
        lines.push(String::new());
        lines.push("tun:".into());
        lines.push(format!("  enabled: {}", self.tun_enabled));
        lines.push(String::new());
        if self.tun_dns {
            lines.push("dns:".into());
            lines.push("  enabled: true".into());
            lines.push(String::new());
        }
        lines.push("transports:".into());
        lines.push("  rfcomm:".into());
        lines.push(format!("    mode: \"{}\"", self.role));
        lines.push(format!("    channel: {}", self.channel));
        lines.push("    mtu: 1000".into());
        if self.role == "server" {
            lines.push("    accept_connections: true".into());
        } else {
            lines.push("    auto_connect: true".into());
        }
        if !self.peers.is_empty() {
            lines.push("    peers:".into());
            for peer in &self.peers {
                lines.push(format!("      - mac: \"{}\"", peer.bt_mac));
            }
        }
        lines.push(String::new());
        if !self.peers.is_empty() {
            lines.push("peers:".into());
            for peer in &self.peers {
                lines.push(format!("  - npub: \"{}\"", peer.npub));
                if !peer.alias.is_empty() {
                    lines.push(format!("    alias: \"{}\"", peer.alias));
                }
                lines.push("    addresses:".into());
                lines.push("      - transport: serial".into());
                lines.push(format!("        addr: \"{}\"", peer.bt_mac));
                lines.push("    connect_policy: auto_connect".into());
            }
        } else {
            lines.push("peers: []".into());
        }
        lines.push(String::new());
        if self.tun_gateway {
            lines.push("gateway:".into());
            lines.push("  enabled: true".into());
            lines.push("  pool: \"fd01::/112\"".into());
            lines.push("  lan_interface: \"br-lan\"".into());
            lines.push("  dns:".into());
            lines.push("    listen: \"[::1]:5353\"".into());
            lines.push("    upstream: \"[::1]:5354\"".into());
            lines.push("    ttl: 60".into());
            lines.push(String::new());
        }
        if self.role == "server" {
            lines.push("peers_allow: /etc/fips/peers.allow".into());
            lines.push(String::new());
        }
        lines.join("\n")
    }

    /// The server-mode peers.allow content (one npub per line).
    pub(super) fn peers_allow(&self) -> String {
        if self.role != "server" {
            return String::new();
        }
        let npubs: Vec<&str> = self
            .peers
            .iter()
            .filter(|p| !p.npub.is_empty())
            .map(|p| p.npub.as_str())
            .collect();
        if npubs.is_empty() {
            return String::new();
        }
        format!("{}\n", npubs.join("\n"))
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
    pub(super) fn derived_price_checked(&self) -> Result<Option<(u32, &'static str)>, Unsupported> {
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

/// Deterministic per-device identity — port of the 1.x `fleet_identity`
/// use case (`scripts/use_cases/fleet_identity.py`; host twin
/// `scripts/fleet_secrets.py`): MAC-derived root password + hostname +
/// optional management AP + rogue-DHCP disarm, in ONE ash invocation
/// (the derivations must share a process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetIdentityProfile {
    /// Fleet salt, 8-128 chars of `[A-Za-z0-9_-]` (single-quote-safe).
    pub salt: String,
    /// Hostname prefix (`[a-z0-9][a-z0-9-]{0,19}`).
    pub hostname_prefix: String,
    /// Management-AP SSID prefix (defaults to the hostname prefix).
    pub ssid_prefix: String,
    /// Wifi domain name for the AP key derivation.
    pub wifi_network: String,
    /// Derived-password length, 8..=32 (1.x default 20).
    pub password_length: u32,
    /// Disarm rogue DHCP (dhcp.lan.ignore + ra/dhcpv6 disabled).
    pub disarm_dhcp: bool,
    /// Configure the guarded management AP block.
    pub configure_ap: bool,
}

impl Default for FleetIdentityProfile {
    fn default() -> Self {
        Self {
            salt: String::new(),
            hostname_prefix: "fleet".into(),
            ssid_prefix: String::new(),
            wifi_network: "fleet".into(),
            password_length: 20,
            disarm_dhcp: true,
            configure_ap: true,
        }
    }
}

impl FleetIdentityProfile {
    pub(crate) fn validate(&self) -> Result<(), Unsupported> {
        let bad = |why: &str| Unsupported::InvalidParams(why.into());
        let salt_ok = (8..=128).contains(&self.salt.len())
            && self
                .salt
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
        if !salt_ok {
            return Err(bad(
                "salt must be 8-128 chars of [A-Za-z0-9_-] (openssl rand -hex 16)",
            ));
        }
        let prefix_ok = |v: &str| {
            (1..=20).contains(&v.len())
                && v.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && v.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        if !prefix_ok(&self.hostname_prefix) {
            return Err(bad("hostname_prefix must match [a-z0-9][a-z0-9-]{0,19}"));
        }
        if !self.ssid_prefix.is_empty() && !prefix_ok(&self.ssid_prefix) {
            // empty = "use hostname_prefix" (1.x `or` fallback); the
            // resolved value is then the already-validated prefix.
            return Err(bad("ssid_prefix must match [a-z0-9][a-z0-9-]{0,19}"));
        }
        let net_ok = (1..=16).contains(&self.wifi_network.len())
            && self
                .wifi_network
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !net_ok {
            return Err(bad("wifi_network must match [a-z0-9][a-z0-9-]{0,15}"));
        }
        if !(8..=32).contains(&self.password_length) {
            return Err(bad("password_length must be 8..=32"));
        }
        Ok(())
    }
}

/// TollGate cellular upstream — port of the 1.x `tollgate-cellular`
/// use case (`scripts/use_cases/tollgate_cellular.py`, bench-validated
/// on the NR7101 2026-10-24): Quectel-class modem as ECM WAN with SIM
/// slot and APN via the AT port (NEVER uqmi — the hang class), one-shot
/// idempotent modem setup, optional SIM balance tooling, and hotplug
/// re-up.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TollgateCellularProfile {
    /// APN for cid 1 (modem auto-dial in ECM mode).
    pub apn: String,
    /// Dual-slot modems: slot holding the profile card ("" = skip).
    pub sim_slot: String,
    /// UCI network iface for the modem WAN (1.x default `wan`).
    pub wan_iface: String,
    /// USB ECM interface the modem enumerates (1.x default `usb0`).
    pub usb_iface: String,
    /// SIM ICCID — non-empty stages sim.json + the balance tooling.
    pub iccid: String,
    /// Provider label for sim.json.
    pub provider: String,
    /// SIM EID for sim.json.
    pub eid: String,
    /// Provider balance API URL template ({{iccid}} substituted on-device).
    pub balance_api: String,
    /// Optional wired-side management IP (also configures network.lan).
    pub management_ip: String,
}

impl Default for TollgateCellularProfile {
    fn default() -> Self {
        Self {
            apn: String::new(),
            sim_slot: String::new(),
            wan_iface: "wan".into(),
            usb_iface: "usb0".into(),
            iccid: String::new(),
            provider: String::new(),
            eid: String::new(),
            balance_api: String::new(),
            management_ip: String::new(),
        }
    }
}

impl TollgateCellularProfile {
    pub(crate) fn validate(&self) -> Result<(), Unsupported> {
        let bad = |why: &str| Unsupported::InvalidParams(why.into());
        // Every string lands in single-quoted shell or uci values.
        for v in [
            &self.apn,
            &self.sim_slot,
            &self.iccid,
            &self.provider,
            &self.eid,
            &self.balance_api,
            &self.management_ip,
        ] {
            if v.contains('\'') || v.contains('\\') || v.contains('"') {
                return Err(bad(
                    "tollgate-cellular string params must not contain quotes/backslashes",
                ));
            }
        }
        let iface_ok = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        if !iface_ok(&self.wan_iface) || !iface_ok(&self.usb_iface) {
            return Err(bad("wan_iface/usb_iface must be plain interface names"));
        }
        Ok(())
    }
}
