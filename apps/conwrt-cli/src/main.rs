//! # conwrt (Rust CLI)
//!
//! Thin frontend over the conwrt engine (ADR-0008). M1 surface is
//! deliberately read-only and mock-backed:
//!
//! - `conwrt models validate` — validate the shared `models/*.json` corpus
//!   (parity with `make validate-models`).
//! - `conwrt identify --mac …` — OUI-prefix model identification.
//! - `conwrt probe --scenario …` — run the diagnostic workflow against a
//!   scripted mock provider (demonstrates the capability-provider swap;
//!   local-std and remote providers arrive in M2/M3).
//! - `conwrt plan --profile sqm …` — plan a desired-state profile for a
//!   diagnosed device: typed, inspectable operations, verification intent,
//!   and a hard refusal for anything but a confirmed OpenWrt identity
//!   (I/O-free dry-run; the M7 executor applies plans later).
//! - `conwrt maas flash …` / `conwrt maas vm …` — MAAS portable-lab
//!   operations (#169): the verify→write→verify→inject disk pipeline and
//!   the VM lifecycle (create/list/describe/destroy) over a region API.

use clap::{Parser, Subcommand, ValueEnum};
use conwrt_core::mock::{MockProber, NamedScenario};
use conwrt_core::plan::{
    AdguardProfile, AutoSqmProfile, CashuVpnClientProfile, DohProfile, GuestWifiProfile,
    MptcpBondingProfile, Mwan3Profile, NodnsProfile, OpenClashProfile, PbrProfile,
    RescueWatchdogProfile, SqmProfile, SshHardeningProfile, SslProfile, TollgateProfile,
    TollgateSecurityProfile, TravelmateProfile, VpnNordvpnOpenvpnProfile, VpnNordvpnProfile,
    VpnPiaOpenvpnProfile, VpnPiaProfile, WireguardClientProfile, WireguardServerProfile,
};
use conwrt_core::ssh::{HostKeyView, TrustMode, TrustStore};
use conwrt_core::{DeviceState, Profile, confirm, diagnose, plan_profile};
use conwrt_local_std::fingerprint::fingerprint;

mod watch;
mod zycast;
use conwrt_local_std::ssh::{SshOptions, SshTarget, connect, resolve_auth};
use conwrt_local_std::trust::FileTrustStore;
use core::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "conwrt",
    version,
    about = "Router lifecycle framework (Conwrt 2.0 engine, M1 slice)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
/// Device-profile search path: ./devices then ~/.config/conwrt/devices
/// (first hit wins; one source of truth for CLI arms — review round-3).
fn default_device_search_path() -> Vec<std::path::PathBuf> {
    vec![
        std::path::PathBuf::from("."),
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".config/conwrt"))
            .unwrap_or_else(|| std::path::PathBuf::from(".config/conwrt")),
    ]
}

#[derive(Subcommand)]
enum Command {
    /// List or dump /dev/mtd partitions over serial (Rust port of
    /// scripts/serial-backup.py).

    /// Detect the likely baud rate of a serial console: opens the port at
    /// each candidate rate, scores received data (ComScope/baudowl
    /// scoring; Rust port of scripts/serial_baud.py).
    SerialBaud {
        /// Serial port spec (local /dev only).
        #[arg(long)]
        port: String,
        /// Seconds to listen per candidate rate.
        #[arg(long, default_value_t = 3)]
        listen_secs: u32,
    },
    /// First-contact configuration over serial (Rust port of
    /// scripts/serial-configure.py): show state, set LAN IP, toggle
    /// password auth, install an SSH key.

    /// Serial console monitor: dual logging (raw + timestamped), boot-stage
    /// detection, stdin line injection with ESCAPE/ENTER/CTRLC tokens
    /// (Rust port of scripts/serial-console.py --monitor).

    /// U-Boot serial flash stage (RAM-only): BREAK-reboot ladder,
    /// loady + YMODEM the image, size + iminfo gates, explicit-address
    /// bootm. Bench-proven on the GS1900-8HP/RTL8382M 2026-10-23.
    UbootLoady {
        /// Serial port spec, e.g. /dev/serial/by-id/usb-FTDI_...-port0.
        #[arg(long)]
        port: String,
        /// Baud rate (GS1900 console: 115200).
        #[arg(long, default_value_t = 115200)]
        baud: u32,
        /// RAM load address for loady (GS1900: 0x84f00000).
        #[arg(long, default_value = "0x84f00000")]
        addr: String,
        /// Image file to YMODEM (initramfs-kernel.bin for a boot test).
        #[arg(long)]
        image: String,
        /// Remote file name advertised in the YMODEM header.
        #[arg(long, default_value = "openwrt-initramfs.bin")]
        name: String,
        /// Extra U-Boot commands to run BEFORE loady (e.g. "setsys bootpartition 0").
        #[arg(long = "pre")]
        pre: Vec<String>,
        /// Boot the image after the gates pass (bootm <addr>).
        #[arg(long, default_value_t = true)]
        boot: bool,
    },
    /// Read-only device detection: classify the console (U-Boot / Linux
    /// shell / booting / silent) and, when a prompt answers, collect the
    /// device card — banner, env, kernel, release, MTD layout — as JSON.
    SerialDetect {
        /// Serial port spec (/dev/... or tcp://HOST:PORT).
        #[arg(long)]
        port: String,
        #[arg(long, default_value_t = 115200)]
        baud: u32,
        #[arg(long, default_value_t = 4.0)]
        probe_secs: f64,
        /// Enable profile fingerprint matching (./devices then
        /// ~/.config/conwrt/devices).
        #[arg(long)]
        devices: bool,
    },
    /// One-command rescue: the whole bench-proven RTL838x ladder —
    /// watch for the boot signature, spaces into U-Boot, bundled
    /// TFTP server + gated tftpboot of the initramfs, bootm, then
    /// fetch the sysupgrade image over the same wire, on-box sha
    /// gate, self-firing sysupgrade -n. No recipe file needed.
    FlashRescue {
        /// Serial port spec (/dev/... or tcp://HOST:PORT or telnet://).
        #[arg(long)]
        port: String,
        /// Device profile name (e.g. zyxel/gs1900-8hp) — resolved from
        /// ./devices/ then ~/.config/conwrt/devices/.
        #[arg(long, default_value = "zyxel/gs1900-8hp")]
        device: String,
        /// Rescue from a LIVE shell (box already at root@OpenWrt):
        /// wget + on-box sha gate + self-firing sysupgrade, instead of
        /// the boot-watch ladder.
        #[arg(long)]
        at_shell: bool,
        /// Sysupgrade image path, SERVED over http :8022 from --serve-dir
        /// (file name only is used in the on-box wget).
        #[arg(long)]
        sysupgrade: String,
        /// sha256 of the sysupgrade image (the on-box gate).
        #[arg(long)]
        sha256: String,
        /// Initramfs image file name inside --serve-dir (tftpboot target).
        #[arg(long, default_value = "")]
        initramfs: String,
        /// Directory served by the bundled TFTP (:69) and expected on
        /// http :8022 (external server; bundled http is future work).
        #[arg(long)]
        serve_dir: String,
        /// Host IP the box reaches (serverip + wget host).
        #[arg(long)]
        server_ip: String,
        /// Switch IP (ipaddr).
        #[arg(long, default_value = "192.168.1.1")]
        client_ip: String,
        /// Transcript file.
        #[arg(long, default_value = "/tmp/conwrt-flash-rescue.transcript")]
        transcript: String,
    },
    /// Event-driven serial supervisor: watch the console for a boot
    /// signature and fire a staged recovery recipe the instant it
    /// matches — in-process, no subprocess latency (the bootdelay
    /// lesson: the window is ~1 s). Recipes are JSON (see recipes/).
    SerialWatch {
        /// Serial port spec (/dev/... or tcp://HOST:PORT for ser2net).
        #[arg(long)]
        port: String,
        /// Baud (ignored for tcp://).
        #[arg(long, default_value_t = 115200)]
        baud: u32,
        /// Recipe JSON path (triggers + actions).
        #[arg(long)]
        recipe: String,
        /// Transcript file (console capture + watch log, appended).
        #[arg(long, default_value = "/tmp/conwrt-serial-watch.transcript")]
        transcript: String,
        /// Idle poll interval in seconds.
        #[arg(long, default_value_t = 0.5)]
        poll_secs: f64,
    },
    /// Wedge recovery: reboot a livelocked device via UART BREAK + sysrq-b
    /// (RTL8382 field-proven 25+ times; works when console input is dead).
    SerialRecover {
        /// Serial port spec, e.g. /dev/serial/by-id/usb-FTDI_...-port0.
        #[arg(long)]
        port: String,
        /// Baud rate (GS1900 console: 115200).
        #[arg(long, default_value_t = 115200)]
        baud: u32,
        /// Boot marker(s) to wait for after the reboot; comma-separated
        /// matches ANY (default: the standard boot-start set — kernel
        /// handoff, bootloader banner, procd init).
        #[arg(
            long,
            default_value = "Starting kernel,U-Boot,procd: - init,init: - preinit"
        )]
        marker: String,
        /// Overall timeout in seconds.
        #[arg(long, default_value_t = 240)]
        timeout: u32,
    },
    /// Validate device model JSON files against the model schema.
    Models {
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// Identify model candidates for a MAC address (OUI prefix match).
    Identify {
        /// MAC address, e.g. `94:83:C4:00:11:22`.
        #[arg(long)]
        mac: String,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// Run the read-only diagnostic workflow against the local network
    /// interfaces (real provider — Linux/macOS).
    Diagnose {
        /// Target address to probe.
        #[arg(long)]
        ip: IpAddr,
        /// Interface used for carrier/ARP queries (e.g. enp5s0, en0).
        #[arg(long)]
        interface: Option<String>,
        /// HTTP port to probe (80; override for OEM/recovery servers).
        #[arg(long, default_value_t = 80)]
        http_port: u16,
        /// SSH port to probe for the identification banner (22).
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// Private key for the authenticated board read: when the
        /// unauthenticated verdict is `ssh-only`, connect with this key
        /// and read board identity (`/tmp/sysinfo/board_name` +
        /// `/etc/openwrt_release`) to resolve the OS ambiguity.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// IPv6 dark-device discovery (#156): probe-host self-check, active
    /// Router Solicitation (rdisc6), RA decode, EUI-64 derivation, banner
    /// probes. The tool that would have turned the 2026-10-12 x1860
    /// incident into a ten-second diagnosis.
    DiscoverV6 {
        /// Interface to probe (e.g. enp5s0).
        #[arg(long)]
        interface: String,
        /// Optionally derive the EUI-64 link-local for a MAC seen on the
        /// wire (ARP/dump) and banner-probe it — works even with NO RA.
        #[arg(long)]
        mac: Option<String>,
        /// Also probe these TCP ports on the discovered router link-local.
        #[arg(long, value_delimiter = ',', default_value = "22,80")]
        ports: Vec<u16>,
    },
    /// Agent controller subcommands (#108).
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// MAAS portable-lab operations (#169): lab disk flashing and the VM
    /// lifecycle (compose/deploy/list/describe/destroy) over the region API.
    Maas {
        #[command(subcommand)]
        command: MaasCommand,
    },
    /// Manage the firmware images cache (1.x `conwrt.py cache` parity).
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Source the vanilla OpenWrt image for a model from
    /// downloads.openwrt.org: resolve release/flavour through the
    /// precedence chains (CLI > env > model > default), fetch the
    /// target's sha256sums index, verify the downloaded bytes, cache
    /// under images/ (1.x `conwrt.py image` / `make source-image` parity).
    SourceImage {
        /// Model id from `conwrt models`.
        #[arg(long)]
        model_id: String,
        /// Full X.Y.Z release; defaults to the model's `openwrt.release`.
        #[arg(long)]
        release: Option<String>,
        /// Image flavour (e.g. squashfs-factory.bin); defaults to the
        /// model's `openwrt.image_suffix`, then squashfs-sysupgrade.bin.
        #[arg(long)]
        image_suffix: Option<String>,
        /// Images cache root (default: `images/`).
        #[arg(long, default_value = "images")]
        images_root: PathBuf,
        /// downloads server base URL (default: downloads.openwrt.org;
        /// mirrors work — the layout below `<base>/releases/` is the
        /// contract).
        #[arg(long)]
        downloads_base: Option<String>,
        /// Skip the sha256sums index check (parity with the 1.x kwarg).
        #[arg(long)]
        no_verify: bool,
        /// Re-download even when a matching cached image exists.
        #[arg(long)]
        force: bool,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// Request a custom ASU firmware build and cache the verified image
    /// (#117 parity slice for firmware-manager.py `request`).
    Image {
        /// Model id from `conwrt models` (resolves target/profile/version).
        #[arg(long)]
        model_id: String,
        /// OpenWrt release; defaults to the model's `openwrt.version`.
        #[arg(long)]
        release: Option<String>,
        /// Comma-separated extra packages baked into the image.
        #[arg(long, value_delimiter = ',')]
        packages: Vec<String>,
        /// First-boot defaults script file (uci commands), baked in.
        #[arg(long)]
        defaults: Option<PathBuf>,
        /// Images cache root (default: `images/`).
        #[arg(long, default_value = "images")]
        images_root: PathBuf,
        /// ASU base URL (default: the public instance; env
        /// CONWRT_ASU_BASE overrides; tests point this at a mock).
        #[arg(long, env = "CONWRT_ASU_BASE")]
        asu_base: Option<String>,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// Run the read-only diagnostic workflow against a scripted provider.
    Probe {
        /// Target address (used for reporting; the mock answers anything).
        #[arg(long, default_value = "192.168.1.1")]
        ip: IpAddr,
        /// Which scripted scenario the mock provider answers with.
        #[arg(long, default_value = "uboot")]
        scenario: ScenarioChoice,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// ZyXEL Multiboot multicast flash sender (Rust port of cmd/zycast;
    /// framing golden-pinned to the Go reference). Bounded loops by
    /// design — the bootloader listens on EVERY boot, so never leave a
    /// sender running.
    Zycast {
        /// Firmware image to multicast.
        image: PathBuf,
        /// Egress interface (SO_BINDTODEVICE).
        #[arg(long, short = 'i')]
        interface: String,
        /// Image type: bootbase|rom|ras|romd|backup.
        #[arg(long, short = 't', default_value = "ras")]
        image_type: String,
        /// Send loops before stopping.
        #[arg(long, default_value_t = conwrt_zycast::DEFAULT_LOOPS)]
        loops: u32,
        /// Inter-packet delay in milliseconds.
        #[arg(long, default_value_t = conwrt_zycast::DEFAULT_DELAY_MS)]
        delay_ms: u64,
        /// Multicast group.
        #[arg(long, short = 'g', default_value = conwrt_zycast::DEFAULT_GROUP)]
        group: String,
        /// Multicast port.
        #[arg(long, short = 'p', default_value_t = conwrt_zycast::DEFAULT_PORT)]
        port: u16,
        /// Attest that the target specimen is verified (MAC/serial gate)
        /// and sibling units are isolated. Required: the multicast hits
        /// every ZyXEL bootloader in its listen window on the segment.
        #[arg(long)]
        confirm_specimen: bool,
    },
    /// Dark-watch: watch a dark/flapping target over time and classify WHY
    /// it is dark (boot loop with cycle period / hung after boot / silent /
    /// inconclusive). The dark-device doctrine is built in: silence only
    /// counts when the capture path is proven by foreign traffic.
    DarkWatch {
        /// Target IPv4 address.
        #[arg(long, default_value = "192.168.1.1")]
        ip: String,
        /// Interface for the passive stream and positive control.
        #[arg(long)]
        interface: String,
        /// Watch duration in seconds.
        #[arg(long, default_value_t = 180)]
        duration: u64,
        /// Seconds between active probes.
        #[arg(long, default_value_t = 5)]
        interval: u64,
    },
    /// Apply a desired-state profile to a device over SSH. DRY-RUN by
    /// default: prints the exact script. Mutating execution requires
    /// --execute AND a fingerprint-confirmed OpenWrt identity.
    Apply {
        #[command(flatten)]
        profile_args: ProfileArgs,
        /// Explicitly forget the stored host key before connecting
        /// (reflash/reimage escape hatch; logged, never silent).
        #[arg(long)]
        relearn_host_key: bool,
        /// Model to plan for (id from `conwrt models`).
        #[arg(long)]
        model_id: String,
        /// Target address of the device.
        #[arg(long)]
        ip: IpAddr,
        /// SSH port.
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Login user (OpenWrt default: root).
        #[arg(long, default_value = "root")]
        user: String,
        /// Private key file for auth (omit to use password auth).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Password for auth (ignored when --key is given; env
        /// CONWRT_SSH_PASSWORD as fallback).
        #[arg(long)]
        password: Option<String>,
        /// Actually execute the mutating script (default is dry-run).
        #[arg(long)]
        execute: bool,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
    /// Fingerprint a device over SSH with authenticated, read-only evidence
    /// (TOFU host keys persist in ~/.config/conwrt/known_hosts —
    /// $CONWRT_KNOWN_HOSTS overrides)
    /// (OpenWrt release, board name, hostname) — the confirming layer above
    /// the passive probe: upgrades an unconfirmed `ssh-only` classification.
    Fingerprint {
        /// Target address of the device.
        #[arg(long)]
        ip: IpAddr,
        /// Explicitly forget the stored host key for this device before
        /// connecting (the reflash/reimage escape hatch). TOFU re-learns
        /// on success. Never silent: the action is logged.
        #[arg(long)]
        relearn_host_key: bool,
        /// SSH port.
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Login user (OpenWrt default: root).
        #[arg(long, default_value = "root")]
        user: String,
        /// Private key file for auth (omit to use password auth).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Password for auth (ignored when --key is given; env
        /// CONWRT_SSH_PASSWORD as fallback).
        #[arg(long)]
        password: Option<String>,
    },
    Plan {
        #[command(flatten)]
        profile_args: ProfileArgs,
        /// Model to plan for (id from `conwrt models`).
        #[arg(long)]
        model_id: String,
        /// Target address (used for reporting; the mock answers anything).
        #[arg(long, default_value = "192.168.1.1")]
        ip: IpAddr,
        /// Which scripted scenario the mock provider answers with.
        #[arg(long, default_value = "openwrt")]
        scenario: ScenarioChoice,
        /// Directory containing `*.json` model files.
        #[arg(long, default_value = "models")]
        dir: PathBuf,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScenarioChoice {
    Off,
    Unreachable,
    Uboot,
    Openwrt,
    SshOnly,
    Stock,
}
impl ScenarioChoice {
    fn named(self) -> NamedScenario {
        match self {
            ScenarioChoice::Off => NamedScenario::Off,
            ScenarioChoice::Unreachable => NamedScenario::Unreachable,
            ScenarioChoice::Uboot => NamedScenario::UbootRecovery,
            ScenarioChoice::Openwrt => NamedScenario::OpenWrt,
            ScenarioChoice::SshOnly => NamedScenario::SshOnly,
            ScenarioChoice::Stock => NamedScenario::StockVendor,
        }
    }
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProfileChoice {
    Sqm,
    Doh,
    SshHardening,
    Adguard,
    RescueWatchdog,
    WireguardClient,
    WireguardServer,
    GuestWifi,
    Travelmate,
    Pbr,
    Mwan3,
    Nodns,
    AutoSqm,
    /// 1.x use-case name is one word (`openclash`), not kebab-case.
    #[value(name = "openclash")]
    OpenClash,
    Ssl,
    /// 1.x spelling: hyphenated multi-word profile name.
    #[value(name = "vpn-pia-openvpn")]
    VpnPiaOpenvpn,
    CashuVpnClient,
    /// 1.x preset name (one word, kebab by default).
    VpnNordvpn,
    /// 1.x spelling.
    #[value(name = "vpn-nordvpn-openvpn")]
    VpnNordvpnOpenvpn,
    /// 1.x preset name (kebab by default).
    VpnPia,
    MptcpBonding,
    Tollgate,
    TollgateSecurity,
}

/// Profile selection + per-profile parameters, shared by `apply` and
/// `plan` (flattened into both subcommands — one help surface, one
/// `build_profile` consumer).
#[derive(clap::Args)]
struct ProfileArgs {
    /// Desired-state profile to apply.
    #[arg(long)]
    profile: ProfileChoice,
    /// Shaper download rate in Kbit/s (required for sqm).
    #[arg(long)]
    download_kbps: Option<u32>,
    /// Shaper upload rate in Kbit/s (required for sqm).
    #[arg(long)]
    upload_kbps: Option<u32>,
    /// UCI network name to shape (sqm).
    #[arg(long, default_value = "wan")]
    interface: String,
    /// DoH provider name or https:// URL (doh).
    #[arg(long)]
    provider: Option<String>,
    /// DoH local listen port (doh); ssh-hardening dropbear port;
    /// wireguard-server UDP listen port.
    #[arg(long)]
    listen_port: Option<u16>,
    /// ssh-hardening: idle disconnect timeout in seconds.
    #[arg(long)]
    idle_timeout: Option<u32>,
    /// ssh-hardening: max auth attempts per connection.
    #[arg(long)]
    max_auth_tries: Option<u32>,
    /// ssh-hardening: KEEP password auth (default disables it).
    #[arg(long)]
    password_auth: bool,
    /// adguard: web UI listen address.
    #[arg(long)]
    listen_ip: Option<String>,
    /// adguard: web UI port.
    #[arg(long)]
    web_port: Option<u16>,
    /// adguard: DNS listen port (off 53 to avoid dnsmasq).
    #[arg(long)]
    dns_port: Option<u16>,
    /// rescue-watchdog: management IP pinged once a minute.
    #[arg(long)]
    target: Option<String>,
    /// wireguard-client: VPN server public key (required).
    #[arg(long)]
    peer_public_key: Option<String>,
    /// wireguard-client: VPN server hostname or IPv4 (required).
    #[arg(long)]
    endpoint_host: Option<String>,
    /// wireguard-client: VPN server UDP port.
    #[arg(long)]
    endpoint_port: Option<u16>,
    /// cashu-vpn-client: tunnel IP assigned by the VPN exit, with CIDR
    /// (from the paid `POST /peer` response; required).
    #[arg(long)]
    peer_ip: Option<String>,
    /// wireguard-client: pre-shared key (optional).
    #[arg(long)]
    peer_psk: Option<String>,
    /// wireguard-client: tunnel address with CIDR.
    #[arg(long)]
    address: Option<String>,
    /// wireguard-client: DNS server through the tunnel.
    #[arg(long)]
    dns: Option<String>,
    /// wireguard-client: IPs routed through the tunnel.
    #[arg(long)]
    allowed_ips: Option<String>,
    /// wireguard-client: opt OUT of the kill switch (1.x default is ON —
    /// block all traffic when the tunnel is down).
    #[arg(long)]
    no_kill_switch: bool,
    /// wireguard-server: VPN client subnet, server IP + CIDR.
    #[arg(long)]
    subnet: Option<String>,
    /// wireguard-server: first peer's public key (empty = no peer).
    #[arg(long)]
    peer1_public_key: Option<String>,
    /// wireguard-server: first peer's allowed IPs.
    #[arg(long)]
    peer1_allowed_ips: Option<String>,
    /// wireguard-server: first peer's pre-shared key (optional).
    #[arg(long)]
    peer1_psk: Option<String>,
    /// guest-wifi: SSID (required; validated at plan time).
    #[arg(long)]
    ap_ssid: Option<String>,
    /// guest-wifi: WiFi password (empty = open network).
    #[arg(long)]
    ap_key: Option<String>,
    /// guest-wifi: encryption mode (psk2 default, sae for WPA3…).
    #[arg(long)]
    ap_encryption: Option<String>,
    /// guest-wifi: WiFi band (2.4ghz default).
    #[arg(long)]
    ap_band: Option<String>,
    /// guest-wifi: opt OUT of client isolation (default isolates).
    #[arg(long)]
    ap_no_isolation: bool,
    /// pbr: WAN UCI interface for default routing (default `wan`).
    #[arg(long)]
    pbr_wan: Option<String>,
    /// mwan3: primary WAN interface (default `wan`).
    #[arg(long)]
    mwan3_primary: Option<String>,
    /// mwan3: secondary WAN interface (default `usbwan`).
    #[arg(long)]
    mwan3_secondary: Option<String>,
    /// mwan3: `failover` or `balanced` (default `failover`).
    #[arg(long)]
    mwan3_policy: Option<String>,
    /// nodns: DNS zone to cache (default `nodns.shop`).
    #[arg(long)]
    nodns_zone: Option<String>,
    /// nodns: bot API base URL (default `https://nodns.shop`).
    #[arg(long)]
    nodns_api_url: Option<String>,
    /// nodns: polling interval in seconds, 60–86400 (default 300).
    #[arg(long)]
    nodns_poll_interval: Option<u32>,
    /// auto-sqm: `static` or `dynamic` (default `static`).
    #[arg(long)]
    autosqm_mode: Option<String>,
    /// auto-sqm: WAN interface to measure/shape (default `wan`).
    #[arg(long)]
    autosqm_interface: Option<String>,
    /// auto-sqm: apply SQM at this % of measured speed (default 90).
    #[arg(long)]
    autosqm_target_percent: Option<u32>,
    /// openclash: default proxy protocol (default `ss`).
    #[arg(long)]
    openclash_proxy_type: Option<String>,
    /// openclash: Clash core — Meta, Dev, or Tun (default `Meta`).
    #[arg(long)]
    openclash_core_type: Option<String>,
    /// openclash: DNS mode — redir-host or fake-ip (default `redir-host`).
    #[arg(long)]
    openclash_dns_mode: Option<String>,
    /// ssl: cert provider — lancert, qip, or manual (default `lancert`;
    /// cert download/SCP itself is a host-side post-flash step).
    #[arg(long)]
    ssl_provider: Option<String>,
    /// ssl: opt OUT of the uhttpd HTTPS-on-443 wiring (default on).
    #[arg(long)]
    ssl_no_uhttpd_https: bool,
    /// ssl: opt OUT of the nodogsplash port-443 pass-through (default on).
    #[arg(long)]
    ssl_no_443_nds: bool,
    /// vpn-pia-openvpn: PIA username (the p-number; required).
    #[arg(long)]
    pia_ovpn_username: Option<String>,
    /// vpn-pia-openvpn: PIA password (required).
    #[arg(long)]
    pia_ovpn_password: Option<String>,
    /// vpn-pia-openvpn: OpenVPN server port (default 8080).
    #[arg(long)]
    pia_ovpn_port: Option<String>,
    /// vpn-pia-openvpn: upstream gateway IP pinning the endpoint routes.
    #[arg(long)]
    pia_ovpn_gateway: Option<String>,
    /// vpn-pia-openvpn: upstream interface for the route pins (default wan).
    #[arg(long)]
    pia_ovpn_iface: Option<String>,
    /// vpn-pia-openvpn: opt OUT of the kill switch (default on).
    #[arg(long)]
    pia_ovpn_no_kill_switch: bool,
    /// vpn-pia-openvpn: opt OUT of SSH/LuCI access from the VPN zone.
    #[arg(long)]
    pia_ovpn_no_management: bool,
    /// vpn-nordvpn: resolved NordLynx private key (required).
    #[arg(long)]
    nord_private_key: Option<String>,
    /// vpn-nordvpn: server WireGuard public key (required).
    #[arg(long)]
    nord_server_public_key: Option<String>,
    /// vpn-nordvpn: endpoint IP or hostname (required).
    #[arg(long)]
    nord_endpoint_host: Option<String>,
    /// vpn-nordvpn: resolved route-target IP for the endpoint pin (required).
    #[arg(long)]
    nord_route_target: Option<String>,
    /// vpn-nordvpn: endpoint UDP port (default 51820).
    #[arg(long)]
    nord_endpoint_port: Option<String>,
    /// vpn-nordvpn: upstream gateway IP (empty = runtime discovery).
    #[arg(long)]
    nord_gateway: Option<String>,
    /// vpn-nordvpn: upstream interface (default wwan).
    #[arg(long)]
    nord_iface: Option<String>,
    /// vpn-nordvpn: opt OUT of the kill switch (default on).
    #[arg(long)]
    nord_no_kill_switch: bool,
    /// vpn-nordvpn: opt OUT of SSH/LuCI access from the VPN zone.
    #[arg(long)]
    nord_no_management: bool,
    /// vpn-nordvpn-openvpn: resolved service username (required).
    #[arg(long)]
    nordovpn_username: Option<String>,
    /// vpn-nordvpn-openvpn: resolved service password (required).
    #[arg(long)]
    nordovpn_password: Option<String>,
    /// vpn-nordvpn-openvpn: server station IP (required).
    #[arg(long)]
    nordovpn_station: Option<String>,
    /// vpn-nordvpn-openvpn: server hostname for the x509 pin (required).
    #[arg(long)]
    nordovpn_hostname: Option<String>,
    /// vpn-nordvpn-openvpn: udp or tcp (default udp).
    #[arg(long)]
    nordovpn_proto: Option<String>,
    /// vpn-nordvpn-openvpn: OpenVPN cipher (default AES-256-CBC).
    #[arg(long)]
    nordovpn_cipher: Option<String>,
    /// vpn-nordvpn-openvpn: opt OUT of the kill switch (default on).
    #[arg(long)]
    nordovpn_no_kill_switch: bool,
    /// vpn-nordvpn-openvpn: opt OUT of SSH/LuCI access from the VPN zone.
    #[arg(long)]
    nordovpn_no_management: bool,
    /// vpn-pia: PIA username (the p-number; required).
    #[arg(long)]
    pia_username: Option<String>,
    /// vpn-pia: PIA password (required).
    #[arg(long)]
    pia_password: Option<String>,
    /// vpn-pia: PIA region slug (default netherlands).
    #[arg(long)]
    pia_region: Option<String>,
    /// vpn-pia: upstream gateway IP pinning the server route (required).
    #[arg(long)]
    pia_gateway: Option<String>,
    /// vpn-pia: upstream interface (default wwan).
    #[arg(long)]
    pia_iface: Option<String>,
    /// vpn-pia: opt OUT of the kill switch (default on).
    #[arg(long)]
    pia_no_kill_switch: bool,
    /// vpn-pia: opt OUT of SSH/LuCI access from the VPN zone.
    #[arg(long)]
    pia_no_management: bool,
    /// mptcp-bonding: VPS IP (or hostname) running the BSBF server.
    #[arg(long)]
    mptcp_server_ipv4: Option<String>,
    /// mptcp-bonding: client port from `bsbf-add-client` on the VPS.
    #[arg(long)]
    mptcp_server_port: Option<u16>,
    /// mptcp-bonding: client UUID from `bsbf-add-client` on the VPS.
    #[arg(long)]
    mptcp_uuid: Option<String>,
    /// tollgate: nodogsplash gateway name shown to clients.
    #[arg(long)]
    tollgate_gateway_name: Option<String>,
    /// tollgate: nodogsplash gateway domain.
    #[arg(long)]
    tollgate_gateway_domain: Option<String>,
    /// tollgate: client identification (mac, token, ip; default mac).
    #[arg(long)]
    tollgate_clientid: Option<String>,
    /// tollgate: expose SSH (tcp 22) to pre-auth portal clients.
    #[arg(long)]
    tollgate_allow_lan_ssh: bool,
    /// tollgate: opt OUT of the WiFi-STA ifup restart hook.
    #[arg(long)]
    tollgate_no_hotplug: bool,
    /// tollgate: interface whose ifup restarts tollgate-wrt (default wwan).
    #[arg(long)]
    tollgate_hotplug_interface: Option<String>,
    /// tollgate: Cashu mint URL.
    #[arg(long)]
    tollgate_mint_url: Option<String>,
    /// tollgate: Lightning address for payouts.
    #[arg(long)]
    tollgate_lightning_address: Option<String>,
    /// tollgate: price in sats per minute (rendered when != 1).
    #[arg(long)]
    tollgate_price_per_minute: Option<u32>,
    /// tollgate: direct byte price in sats/MiB (0 = derive).
    #[arg(long)]
    tollgate_price_sats_per_mib: Option<u32>,
    /// tollgate: upstream cost USD/GB for derivation (decimal).
    #[arg(long)]
    tollgate_upstream_usd_per_gb: Option<String>,
    /// tollgate: cost multiplier for derivation (default 2.0).
    #[arg(long)]
    tollgate_markup: Option<String>,
    /// tollgate: sats/USD for derivation (required when deriving —
    /// the 2.x planner is I/O-free; pass the 1.x-resolved rate).
    #[arg(long)]
    tollgate_fx_sats_per_usd: Option<u32>,
    /// pbr: LAN interface counted as local traffic (default `lan`).
    #[arg(long)]
    pbr_lan: Option<String>,
    /// travelmate: WiFi radio for upstream scanning.
    #[arg(long)]
    trm_radio: Option<String>,
    /// travelmate: overall retry timeout in seconds.
    #[arg(long)]
    trm_timeout: Option<u32>,
    /// travelmate: retry count to find a suitable uplink.
    #[arg(long)]
    trm_retry: Option<u32>,
    /// travelmate: opt OUT of captive portal detection.
    #[arg(long)]
    trm_no_captive: bool,
}
/// Subcommands of `conwrt cache` (1.x `conwrt.py cache` parity).
#[derive(Subcommand)]
enum CacheCommand {
    /// List cached firmware builds (ASU model/hash layout).
    List {
        /// Images cache root (default: `images/`).
        #[arg(long, default_value = "images")]
        images_root: PathBuf,
    },
    /// Remove cached builds. Without `--yes` only prints the plan.
    Clean {
        /// Restrict to one model (hyphen/underscore spellings both match).
        #[arg(long)]
        model_id: Option<String>,
        /// Keep only the newest build per model (by cache-dir mtime).
        #[arg(long)]
        keep_latest: bool,
        /// Actually remove (otherwise a dry-run preview).
        #[arg(long)]
        yes: bool,
        /// Images cache root (default: `images/`).
        #[arg(long, default_value = "images")]
        images_root: PathBuf,
    },
}

#[derive(Subcommand)]
enum MaasCommand {
    /// Run the lab disk pipeline (verify → write → verify → inject) on a
    /// target file or device. The image is checksum-gated before ANY
    /// write; a seed is injected only after read-back verification.
    Flash {
        /// Image file to write.
        #[arg(long)]
        image: PathBuf,
        /// Published SHA-256 of the image (64 hex chars).
        #[arg(long)]
        sha256: String,
        /// Target file or block device to write. Block-device targets
        /// must pass the specimen gate (USB transport, unmounted,
        /// writable, ≥30GB; serial must match --serial-whitelist when
        /// given) before any write.
        #[arg(long)]
        target: PathBuf,
        /// Comma-separated USB serials allowed as block-device targets
        /// (specimen gate, AGENTS.md MAC/serial rule).
        #[arg(long, value_delimiter = ',')]
        serial_whitelist: Option<Vec<String>>,
        /// cloud-init user-data file (required with --meta-data).
        #[arg(long, requires = "meta_data")]
        user_data: Option<PathBuf>,
        /// cloud-init meta-data file (required with --user-data).
        #[arg(long, requires = "user_data")]
        meta_data: Option<PathBuf>,
        /// Optional cloud-init network-config file (requires the seed
        /// pair --user-data/--meta-data).
        #[arg(long, requires = "user_data")]
        network_config: Option<PathBuf>,
    },
    /// VM lifecycle over the MAAS region API.
    Vm {
        #[command(subcommand)]
        command: VmCommand,
    },
}
#[derive(Subcommand)]
enum VmCommand {
    /// Compose, commission, allocate, and deploy a VM (resolves when
    /// Deployed).
    Create {
        /// Instance hostname (DNS label).
        #[arg(long)]
        name: String,
        /// Virtual CPUs.
        #[arg(long, default_value_t = 2)]
        cores: u16,
        /// Memory in MiB.
        #[arg(long, default_value_t = 2048)]
        memory_mib: u32,
        /// Root disk in GiB.
        #[arg(long, default_value_t = 20)]
        disk_gib: u32,
        /// Region API base, e.g. http://maas-host:5240/MAAS/api/2.0.
        #[arg(long, env = "CONWRT_MAAS_REGION")]
        region: String,
        /// VM host id to compose on.
        #[arg(long, env = "CONWRT_MAAS_VM_HOST")]
        vm_host: String,
        /// Poll interval while awaiting lifecycle states (ms).
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        /// Maximum poll attempts per awaited state.
        #[arg(long, default_value_t = 60)]
        max_polls: u32,
    },
    /// List all machines the region knows.
    List {
        /// Region API base.
        #[arg(long, env = "CONWRT_MAAS_REGION")]
        region: String,
    },
    /// Describe one machine by system_id.
    Describe {
        /// MAAS system_id.
        #[arg(long)]
        system_id: String,
        /// Region API base.
        #[arg(long, env = "CONWRT_MAAS_REGION")]
        region: String,
    },
    /// Release and delete a machine.
    Destroy {
        /// MAAS system_id.
        #[arg(long)]
        system_id: String,
        /// Region API base.
        #[arg(long, env = "CONWRT_MAAS_REGION")]
        region: String,
    },
}
#[derive(Subcommand)]
enum AgentCommand {
    /// Connect to an agent: handshake + list capabilities.
    Info {
        /// Agent address (host:port).
        #[arg(long)]
        addr: String,
    },
    /// Acquire a resource lease.
    Lease {
        /// Agent address (host:port).
        #[arg(long)]
        addr: String,
        /// Resource to lease (e.g. uart0, eth0).
        #[arg(long)]
        resource: String,
        /// Shared (non-exclusive) lease.
        #[arg(long)]
        shared: bool,
        /// Controller identity presented at handshake (default
        /// `conwrt-cli`). Distinct identities prove CROSS-controller
        /// exclusivity — same-id reacquisition is a different code path
        /// (#463).
        #[arg(long)]
        controller: Option<String>,
    },
    /// Query a stream transfer's status (the resume token).
    Status {
        /// Agent address (host:port).
        #[arg(long)]
        addr: String,
        /// Transfer to query.
        #[arg(long)]
        transfer_id: u64,
    },
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::SerialBaud { port, listen_secs } => {
            use conwrt_serial::baud::{COMMON_BAUDS, score_baud_data};
            use conwrt_serial::io::open_port;
            use std::time::Duration;

            // Wake the console (askfirst) and listen at each rate.
            let mut best: Option<(u32, u32)> = None;
            for &rate in COMMON_BAUDS {
                let Ok(mut io) = open_port(&port, rate, Duration::from_millis(500)) else {
                    continue;
                };
                let _ = io.write_all_bytes(b"\r");
                let mut buf = vec![0u8; 8192];
                let mut sample = Vec::new();
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(listen_secs as u64);
                while std::time::Instant::now() < deadline {
                    if let Ok(n) = io.read(&mut buf) {
                        if n > 0 {
                            sample.extend_from_slice(&buf[..n]);
                        }
                    }
                }
                let (score, reason) = score_baud_data(&sample);
                println!("{rate:>7}: {score:>4}  ({reason})");
                if best.is_none_or(|(bs, _)| score > bs) {
                    best = Some((rate, score));
                }
            }
            match best {
                Some((rate, score)) if score > 0 => {
                    println!("best guess: {rate} (score {score})");
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("conwrt: no console data at any candidate rate");
                    ExitCode::from(4)
                }
            }
        }
        Command::UbootLoady {
            port,
            baud,
            addr,
            image,
            name,
            pre,
            boot,
        } => {
            let data = std::fs::read(&image).unwrap_or_else(|e| {
                eprintln!("conwrt: cannot read {image}: {e}");
                std::process::exit(2);
            });
            println!(
                "conwrt: uboot-loady {image} ({} bytes) -> {addr}, boot={boot}",
                data.len()
            );
            match conwrt_serial::uboot::flash_stage_loady(
                &port, baud, &addr, &name, &data, &pre, boot,
            ) {
                Ok(()) => {
                    println!("conwrt: uboot-loady stage complete (RAM-only; flash untouched)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("conwrt: uboot-loady FAILED: {e}");
                    eprintln!("conwrt: gates held — nothing was booted from a bad load");
                    ExitCode::from(5)
                }
            }
        }
        Command::SerialDetect {
            port,
            baud,
            probe_secs,
            devices,
        } => {
            let search = if devices {
                default_device_search_path()
            } else {
                Vec::new()
            };
            match conwrt_serial::detect::detect_with_profiles(&port, baud, probe_secs, &search) {
                Ok(card) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&card).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("conwrt: serial-detect error: {e}");
                    ExitCode::from(5)
                }
            }
        }
        Command::FlashRescue {
            port,
            device,
            at_shell,
            sysupgrade,
            sha256,
            initramfs,
            serve_dir,
            server_ip,
            client_ip,
            transcript,
        } => {
            let fname = std::path::Path::new(&sysupgrade)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| sysupgrade.clone());
            if !std::path::Path::new(&format!("{serve_dir}/{fname}")).exists() {
                eprintln!("conwrt: {serve_dir}/{fname} missing (serve both images from serve_dir)");
                std::process::exit(2);
            }
            // profile search path: cwd, then user config
            let search = default_device_search_path();
            let profile = conwrt_serial::profile::DeviceProfile::load(&device, &search)
                .unwrap_or_else(|e| {
                    eprintln!("conwrt: device profile {device:?}: {e}");
                    std::process::exit(2);
                });
            if !at_shell && initramfs.is_empty() {
                eprintln!(
                    "conwrt: --initramfs is required for the boot-watch ladder (or pass --at-shell)"
                );
                std::process::exit(2);
            }
            if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                eprintln!("conwrt: --sha256 must be 64 hex chars (got {sha256:?})");
                std::process::exit(2);
            }
            let recipe = if at_shell {
                conwrt_serial::watch::flash_from_shell_recipe(
                    &profile, &fname, &sha256, &server_ip, &client_ip,
                )
            } else {
                conwrt_serial::watch::flash_rescue_recipe_from_profile(
                    &profile, &fname, &sha256, &initramfs, &server_ip, &serve_dir, &client_ip,
                )
            };
            println!(
                "conwrt: flash-rescue {} via {initramfs} from {server_ip}",
                recipe.model
            );
            match conwrt_serial::watch::run_watch_with_profile(
                &port,
                profile.console.baud,
                &recipe,
                std::path::Path::new(&transcript),
                1.0,
                Some(&profile),
            ) {
                Ok(out) if out.success => {
                    println!("conwrt: flash-rescue complete: {}", out.detail);
                    ExitCode::SUCCESS
                }
                Ok(out) => {
                    eprintln!("conwrt: flash-rescue failed: {}", out.detail);
                    ExitCode::from(6)
                }
                Err(e) => {
                    eprintln!("conwrt: flash-rescue io error: {e}");
                    ExitCode::from(5)
                }
            }
        }
        Command::SerialWatch {
            port,
            baud,
            recipe,
            transcript,
            poll_secs,
        } => {
            let text = std::fs::read_to_string(&recipe).unwrap_or_else(|e| {
                eprintln!("conwrt: cannot read recipe {recipe}: {e}");
                std::process::exit(2);
            });
            let r: conwrt_serial::watch::Recipe = serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("conwrt: recipe {recipe} does not parse: {e}");
                std::process::exit(2);
            });
            println!(
                "conwrt: serial-watch {} (model {:?}, {} action(s), max_fires {})",
                port,
                r.model,
                r.actions.len(),
                r.max_fires
            );
            match conwrt_serial::watch::run_watch(
                &port,
                baud,
                &r,
                std::path::Path::new(&transcript),
                poll_secs,
            ) {
                Ok(out) => {
                    println!(
                        "conwrt: serial-watch done: fires={} success={} {}",
                        out.fires, out.success, out.detail
                    );
                    if out.success {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(6)
                    }
                }
                Err(e) => {
                    eprintln!("conwrt: serial-watch io error: {e}");
                    ExitCode::from(5)
                }
            }
        }
        Command::SerialRecover {
            port,
            baud,
            marker,
            timeout,
        } => {
            use conwrt_serial::io::open_break_port;
            use conwrt_serial::recovery::reboot_wedged_any;
            use std::time::Duration;

            let mut io = match open_break_port(&port, baud, Duration::from_secs(1)) {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("conwrt: open {port}: {e}");
                    return ExitCode::from(2);
                }
            };
            println!("BREAK + sysrq-b on {port} ...");
            let markers: Vec<&[u8]> = marker
                .split(',')
                .map(|m| m.trim().as_bytes())
                .filter(|m| !m.is_empty())
                .collect();
            match reboot_wedged_any(io.as_mut(), &markers, Duration::from_secs(timeout as u64)) {
                Ok(out) => {
                    println!(
                        "{out:?} - keep this console reader attached until the device is stable."
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("conwrt: recovery: {e}");
                    ExitCode::from(3)
                }
            }
        }
        Command::Models { dir } => cmd_models_validate(&dir),
        Command::Agent { command } => cmd_agent(command),
        Command::Maas { command } => cmd_maas(command),
        Command::Cache { command } => cmd_cache(command),
        Command::SourceImage {
            model_id,
            release,
            image_suffix,
            images_root,
            downloads_base,
            no_verify,
            force,
            dir,
        } => cmd_source_image(
            &SourceImageArgs {
                model_id: &model_id,
                release: release.as_deref(),
                image_suffix: image_suffix.as_deref(),
                images_root: &images_root,
                downloads_base: downloads_base.as_deref(),
                no_verify,
                force,
            },
            &dir,
        ),
        Command::Image {
            model_id,
            release,
            packages,
            defaults,
            images_root,
            asu_base,
            dir,
        } => cmd_image(
            &model_id,
            release.as_deref(),
            &packages,
            defaults.as_deref(),
            &images_root,
            asu_base.as_deref(),
            &dir,
        ),
        Command::Identify { mac, dir } => cmd_identify(&mac, &dir),
        Command::DiscoverV6 {
            interface,
            mac,
            ports,
        } => cmd_discover_v6(&interface, mac.as_deref(), &ports),
        Command::Diagnose {
            ip,
            interface,
            http_port,
            ssh_port,
            key,
            dir,
        } => cmd_diagnose(ip, interface, http_port, ssh_port, key, &dir),
        Command::Probe { ip, scenario, dir } => cmd_probe(ip, scenario, &dir),
        Command::Zycast {
            image,
            interface,
            image_type,
            loops,
            delay_ms,
            group,
            port,
            confirm_specimen,
        } => zycast::run(zycast::ZycastArgs {
            image,
            interface,
            image_type,
            loops,
            delay_ms,
            group,
            port,
            confirm_specimen,
        }),
        Command::DarkWatch {
            ip,
            interface,
            duration,
            interval,
        } => watch::run(watch::WatchArgs {
            ip,
            interface,
            duration_s: duration,
            interval_s: interval,
        }),
        Command::Fingerprint {
            ip,
            relearn_host_key,
            port,
            user,
            key,
            password,
        } => cmd_fingerprint(
            ip,
            relearn_host_key,
            port,
            &user,
            key.as_deref(),
            password.as_deref(),
        ),
        Command::Apply {
            relearn_host_key,
            profile_args,
            model_id,
            ip,
            port,
            user,
            key,
            password,
            execute,
            dir,
        } => cmd_apply(
            relearn_host_key,
            profile_args,
            &model_id,
            ip,
            port,
            &user,
            key.as_deref(),
            password.as_deref(),
            execute,
            &dir,
        ),
        Command::Plan {
            profile_args,
            model_id,
            ip,
            scenario,
            dir,
        } => cmd_plan(profile_args, &model_id, ip, scenario, &dir),
    }
}
fn load_registry(dir: &Path) -> (conwrt_types::registry::ModelRegistry, PathBuf) {
    match conwrt_types::registry::ModelRegistry::load_dir(dir) {
        Ok((registry, invalid)) if invalid.is_empty() => (registry, dir.to_path_buf()),
        Ok((_, invalid)) => {
            eprintln!("invalid models in {}:", dir.display());
            for bad in invalid {
                eprintln!("  {}: {}", bad.path.display(), bad.problems.join("; "));
            }
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}
fn cmd_models_validate(dir: &Path) -> ExitCode {
    let (registry, _) = load_registry(dir);
    let models = registry.models();
    println!(
        "{:<40}  {:<12}  {:<22}  {:<20}  Description",
        "Model ID", "Vendor", "Target", "Flash Methods"
    );
    println!("{}", "-".repeat(140));
    for model in models {
        let target = &model.openwrt.target;
        let methods = model
            .flash_method_names()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<40}  {:<12}  {:<22}  [{}]  {}",
            model.id, model.vendor, target, methods, model.description
        );
    }
    println!("\n{} model(s) valid in {}", models.len(), dir.display());
    ExitCode::SUCCESS
}
fn cmd_identify(mac: &str, dir: &Path) -> ExitCode {
    let mac = match conwrt_types::MacAddress::parse(mac) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let (registry, _) = load_registry(dir);
    let matches = conwrt_core::identify_by_mac(registry.models(), Some(&mac));
    println!("MAC:      {}", mac);
    println!("OUI:      {}", mac.oui());
    if matches.is_empty() {
        println!("candidates: (none — OUI not in the model corpus)");
    } else {
        for m in &matches {
            println!(
                "candidate: {} ({}, via {})",
                m.model_id,
                m.vendor,
                m.kind.as_str()
            );
        }
        println!(
            "\nnote: OUI matches are candidates, not confirmations; \
             board fingerprinting (M2) is the confirming layer"
        );
    }
    ExitCode::SUCCESS
}
fn cmd_probe(ip: IpAddr, scenario: ScenarioChoice, dir: &Path) -> ExitCode {
    let (registry, _) = load_registry(dir);
    let mut prober = MockProber::responding(ip, scenario.named());
    let diagnosis = match pollster::block_on(diagnose(&mut prober, ip, registry.models())) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("probe failed: {e}");
            return ExitCode::from(2);
        }
    };
    print_diagnosis(&diagnosis);
    println!("\n(provider: scripted mock — `conwrt diagnose` uses the local provider)");
    ExitCode::SUCCESS
}
fn cmd_diagnose(
    ip: IpAddr,
    interface: Option<String>,
    http_port: u16,
    ssh_port: u16,
    key: Option<PathBuf>,
    dir: &Path,
) -> ExitCode {
    let (registry, _) = load_registry(dir);
    let mut prober = match interface {
        Some(iface) => conwrt_local_std::LocalProber::on_interface(iface),
        None => conwrt_local_std::LocalProber::global(),
    };
    prober = prober.with_ports(http_port, ssh_port);
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let mut diagnosis = match runtime.block_on(diagnose(&mut prober, ip, registry.models())) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("diagnose failed: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(key_path) = key.as_deref() {
        if diagnosis.state == DeviceState::SshOnly {
            let addr = format!("{ip}:{ssh_port}");
            match runtime.block_on(conwrt_local_std::fingerprint::authenticated_board(
                &addr, key_path,
            )) {
                Some(board) => {
                    diagnosis = conwrt_core::refine_with_authenticated_board(diagnosis, board);
                }
                None => eprintln!(
                    "authenticated board read failed (key refused or unreachable) — \
                     ssh-only verdict stands"
                ),
            }
        }
    }
    print_diagnosis(&diagnosis);
    if key.is_some() {
        println!("\n(provider: local-std; read-only probes + key-authenticated board read)");
    } else {
        println!("\n(provider: local-std; read-only probes — ping, HTTP GET, SSH banner, ARP)");
    }
    ExitCode::SUCCESS
}
fn print_diagnosis(diagnosis: &conwrt_core::Diagnosis) {
    println!("target:     {}", diagnosis.ip);
    if let Some(mac) = diagnosis.mac {
        println!("MAC:        {mac}");
    }
    println!("state:      {}", diagnosis.state.as_str());
    if !matches!(diagnosis.state, DeviceState::Off | DeviceState::Unreachable) {
        println!(
            "evidence:   ping={} http={} ssh={}",
            diagnosis.evidence.ping,
            diagnosis.evidence.http.is_some(),
            diagnosis.evidence.ssh_banner.is_some(),
        );
    }
    for note in &diagnosis.notes {
        println!("note:       {note}");
    }
    if !diagnosis.model_candidates.is_empty() {
        for m in &diagnosis.model_candidates {
            println!("candidate:  {} ({})", m.model_id, m.vendor);
        }
    }
}
fn cmd_plan(
    profile_args: ProfileArgs,
    model_id: &str,
    ip: IpAddr,
    scenario: ScenarioChoice,
    dir: &Path,
) -> ExitCode {
    let (registry, _) = load_registry(dir);
    let model = match registry.models().iter().find(|m| m.id == model_id) {
        Some(m) => m.clone(),
        None => {
            eprintln!("unknown model id {model_id:?} (see `conwrt models`)");
            return ExitCode::from(2);
        }
    };
    let mut prober = MockProber::responding(ip, scenario.named());
    let diagnosis = match pollster::block_on(diagnose(&mut prober, ip, registry.models())) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("probe failed: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match build_profile(&profile_args) {
        Ok(profile) => profile,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match plan_profile(&diagnosis.state, &model, &profile) {
        Ok(plan) => {
            println!("plan:     {} → model {}", plan.profile_id, plan.model_id);
            println!(
                "state:    {} (confirmed OpenWrt identity)",
                diagnosis.state.as_str()
            );
            println!("\noperations:");
            for (i, op) in plan.ops.iter().enumerate() {
                let rendered = op.to_string();
                let mut lines = rendered.lines();
                println!("  {:>2}. {}", i + 1, lines.next().unwrap_or_default());
                for line in lines {
                    println!("      {line}");
                }
            }
            println!("\nverification:");
            for check in &plan.verification {
                println!(
                    "  ✓ {} — `{}` contains {:?}",
                    check.description, check.command, check.expect_contains
                );
            }
            println!("\n(dry-run: planning is I/O-free; the M7 executor applies and verifies)");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("refused: {reason}");
            ExitCode::FAILURE
        }
    }
}
fn default_sqm() -> SqmProfile {
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
fn cmd_fingerprint(
    ip: IpAddr,
    relearn_host_key: bool,
    port: u16,
    user: &str,
    key: Option<&Path>,
    password: Option<&str>,
) -> ExitCode {
    let auth = match resolve_auth(key, password) {
        Ok(auth) => auth,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    let target = SshTarget {
        addr: format!("{ip}:{port}"),
        user: user.to_string(),
        auth,
    };
    if relearn_host_key {
        eprintln!("# relearn-host-key: forgetting stored key for {ip}:{port}");
        store_forget(&target.addr);
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let kh_path = FileTrustStore::default_path();
    let mut store = FileTrustStore::new(kh_path.clone());
    let known_before = store.entries(&target.addr);
    let session = match runtime.block_on(connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("host key:   {}", session.presented_key.fingerprint);
    persist_new_host_key(
        &kh_path,
        &target.addr,
        &session.presented_key,
        &known_before,
    );
    let report = match runtime.block_on(fingerprint(&session)) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("fingerprint failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("target:     {ip}");
    if let Some(release) = &report.release {
        println!(
            "release:    {}",
            release.description.as_deref().unwrap_or("?")
        );
        println!("version:    {}", release.release.as_deref().unwrap_or("?"));
        println!("target:     {}", release.target.as_deref().unwrap_or("?"));
    }
    if let Some(board) = &report.board_name {
        println!("board_name: {board}");
    }
    if let Some(hostname) = &report.hostname {
        println!("hostname:   {hostname}");
    }
    for note in &report.notes {
        println!("note:       {note}");
    }
    let confirmed = confirm(DeviceState::SshOnly, report.release.as_ref());
    println!(
        "identity:   {}",
        if confirmed == DeviceState::OpenWrt {
            "OpenWrt CONFIRMED (authenticated /etc/openwrt_release)"
        } else {
            "OpenWrt NOT confirmed (no authenticated release evidence)"
        }
    );
    ExitCode::SUCCESS
}
fn store_forget(addr: &str) {
    use conwrt_core::ssh::TrustStore;
    FileTrustStore::new(FileTrustStore::default_path()).forget(addr);
}
#[allow(clippy::too_many_arguments)] // ssh-target plumbing; grouped under one subcommand
fn cmd_apply(
    relearn_host_key: bool,
    profile_args: ProfileArgs,
    model_id: &str,
    ip: IpAddr,
    port: u16,
    user: &str,
    key: Option<&Path>,
    password: Option<&str>,
    execute: bool,
    dir: &Path,
) -> ExitCode {
    let (registry, _) = load_registry(dir);
    let model = match registry.models().iter().find(|m| m.id == model_id) {
        Some(m) => m.clone(),
        None => {
            eprintln!("unknown model id {model_id:?} (see `conwrt models`)");
            return ExitCode::from(2);
        }
    };
    let profile = match build_profile(&profile_args) {
        Ok(profile) => profile,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let auth = match resolve_auth(key, password) {
        Ok(auth) => auth,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    let target = SshTarget {
        addr: format!("{ip}:{port}"),
        user: user.to_string(),
        auth,
    };
    if relearn_host_key {
        eprintln!("# relearn-host-key: forgetting stored key for {ip}:{port}");
        store_forget(&target.addr);
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let kh_path = FileTrustStore::default_path();
    let mut store = FileTrustStore::new(kh_path.clone());
    let known_before = store.entries(&target.addr);
    let session = match runtime.block_on(connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("host key:   {}", session.presented_key.fingerprint);
    persist_new_host_key(
        &kh_path,
        &target.addr,
        &session.presented_key,
        &known_before,
    );

    let report = match runtime.block_on(fingerprint(&session)) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("fingerprint failed: {e}");
            return ExitCode::from(2);
        }
    };
    let confirmed = confirm(DeviceState::SshOnly, report.release.as_ref());
    if confirmed != DeviceState::OpenWrt {
        eprintln!(
            "refused: {ip} has no fingerprint-confirmed OpenWrt identity \
             (see `conwrt fingerprint`); refusing to apply a mutating plan"
        );
        return ExitCode::FAILURE;
    }
    if let Some(board) = &report.board_name {
        if !board.is_empty() && !board_matches(&model, board) {
            let expected = board_name_or_device(&model);
            eprintln!(
                "refused: board_name {board:?} does not match model {} board name {expected:?}",
                model.id
            );
            return ExitCode::FAILURE;
        }
    }
    let plan = match plan_profile(&confirmed, &model, &profile) {
        Ok(plan) => plan,
        Err(reason) => {
            eprintln!("planning refused: {reason}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "# plan: {} ops, {} verification checks",
        plan.ops.len(),
        plan.verification.len()
    );
    println!();
    println!("{}", conwrt_local_std::execute::render_apply_script(&plan));

    if !execute {
        println!("# dry-run: no changes made. Re-run with --execute to apply.");
        return ExitCode::SUCCESS;
    }
    // Escape-hatch discipline (AGENTS.md): never disable the only working
    // auth method. Password-only auth + PasswordAuth=off = locked out.
    // The systemic executor-side gate is tracked in #427; this CLI guard
    // covers the concrete foot-gun.
    if let Profile::SshHardening(sh) = &profile {
        if sh.disable_password_auth && key.is_none() {
            eprintln!(
                "refused: ssh-hardening would disable password auth, but this session \
                 authenticates by password (no --key). Install a key first \
                 (conwrt apply --key ... after adding it to authorized_keys) — \
                 refusing to cut the only working door."
            );
            return ExitCode::FAILURE;
        }
    }
    eprintln!("# executing on {ip} ...");
    // #555: network-restarting plans get a deadman + bounded recovery —
    // a severed channel enters a reconnect-and-verify loop within the
    // same window the device-side revert waits.
    let reconnect_target = target.clone();
    let reconnect_kh = kh_path.clone();
    let reconnect = move || {
        let target = reconnect_target.clone();
        let kh_path = reconnect_kh.clone();
        async move {
            let mut store = FileTrustStore::new(kh_path);
            connect(
                &target,
                &mut store,
                &SshOptions {
                    mode: TrustMode::TrustOnFirstUse,
                    ..Default::default()
                },
            )
            .await
        }
    };
    match runtime.block_on(conwrt_local_std::execute::apply_plan_with_recovery(
        &session, &plan, reconnect,
    )) {
        Ok(outcome) if outcome.fully_verified() => {
            if outcome.channel_lost {
                eprintln!(
                    "# channel lost during the apply (network-restart class) — \
                     reconnected within the deadman window and verified good"
                );
            }
            println!("applied:   script exit 0");
            for check in &outcome.verification {
                println!("verified:  ✓ {} (`{}`)", check.description, check.stdout);
            }
            if outcome.deadman_armed {
                println!("deadman:   cancelled (device confirmed)");
            }
            ExitCode::SUCCESS
        }
        Ok(outcome)
            if outcome.applied
                && !outcome.verification.is_empty()
                && outcome.verification.iter().all(|c| c.passed) =>
        {
            // The only way to land here: armed && cancel unconfirmed —
            // readbacks prove the apply landed, but the device still
            // reverts at window expiry. NOT a success (Codex #597 P1).
            eprintln!(
                "apply verified but the deadman cancel is UNCONFIRMED — the device\
                 \nreverts this config when the window expires. Cancel it manually\
                 \nbefore then, or re-run the apply (idempotent):"
            );
            eprintln!(
                "  ssh root@{ip} '{cancel}'",
                cancel = conwrt_local_std::execute::deadman_cancel_cmd()
            );
            ExitCode::FAILURE
        }
        Ok(outcome) => {
            if outcome.channel_lost {
                eprintln!(
                    "apply outcome unknown: the SSH channel closed mid-apply \
                     (network-restart class); deadman armed — the device reverts \
                     its pre-apply uci and restarts networking when the window expires"
                );
            }
            eprintln!(
                "apply incomplete: applied={} — failing checks:",
                outcome.applied
            );
            for check in outcome.verification.iter().filter(|c| !c.passed) {
                eprintln!("  ✗ {}: got {:?}", check.description, check.stdout);
            }
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("apply failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn build_profile(args: &ProfileArgs) -> Result<Profile, String> {
    match args.profile {
        ProfileChoice::Sqm => match (args.download_kbps, args.upload_kbps) {
            (Some(download_kbps), Some(upload_kbps)) => Ok(Profile::Sqm(SqmProfile {
                download_kbps,
                upload_kbps,
                interface: args.interface.clone(),
                ..default_sqm()
            })),
            _ => Err("--download-kbps and --upload-kbps are required for sqm".into()),
        },
        ProfileChoice::Doh => Ok(Profile::Doh(DohProfile {
            provider: args.provider.clone().unwrap_or_else(|| "cloudflare".into()),
            listen_port: args.listen_port.unwrap_or(5053),
        })),
        ProfileChoice::SshHardening => Ok(Profile::SshHardening(SshHardeningProfile {
            disable_password_auth: !args.password_auth,
            idle_timeout: args.idle_timeout.unwrap_or(300),
            max_auth_tries: args.max_auth_tries.unwrap_or(3),
            port: args.listen_port.unwrap_or(22),
            ..SshHardeningProfile::default()
        })),
        ProfileChoice::Adguard => Ok(Profile::Adguard(AdguardProfile {
            listen_ip: args.listen_ip.clone().unwrap_or_else(|| "0.0.0.0".into()),
            web_port: args.web_port.unwrap_or(3000),
            dns_port: args.dns_port.unwrap_or(5353),
        })),
        ProfileChoice::RescueWatchdog => Ok(Profile::RescueWatchdog(RescueWatchdogProfile {
            target: args
                .target
                .clone()
                .unwrap_or_else(|| "192.168.1.254".into()),
        })),
        ProfileChoice::WireguardClient => {
            // required-param gates live in WireguardClientProfile::validate,
            // enforced at plan time with the 1.x error shapes
            Ok(Profile::WireguardClient(WireguardClientProfile {
                peer_public_key: args.peer_public_key.clone().unwrap_or_default(),
                endpoint_host: args.endpoint_host.clone().unwrap_or_default(),
                endpoint_port: args.endpoint_port.unwrap_or(51820),
                peer_psk: args.peer_psk.clone().unwrap_or_default(),
                address: args
                    .address
                    .clone()
                    .unwrap_or_else(|| "10.67.0.2/32".into()),
                dns: args.dns.clone().unwrap_or_default(),
                // 1.x default is ON; --no-kill-switch is the explicit opt-out
                kill_switch: !args.no_kill_switch,
                allowed_ips: args
                    .allowed_ips
                    .clone()
                    .unwrap_or_else(|| "0.0.0.0/0, ::/0".into()),
                ..WireguardClientProfile::default()
            }))
        }
        ProfileChoice::WireguardServer => Ok(Profile::WireguardServer(WireguardServerProfile {
            listen_port: args.listen_port.unwrap_or(51820),
            subnet: args.subnet.clone().unwrap_or_else(|| "10.1.99.1/24".into()),
            peer1_public_key: args.peer1_public_key.clone().unwrap_or_default(),
            peer1_allowed_ips: args
                .peer1_allowed_ips
                .clone()
                .unwrap_or_else(|| "10.1.99.2/32".into()),
            peer1_psk: args.peer1_psk.clone().unwrap_or_default(),
            ..WireguardServerProfile::default()
        })),
        ProfileChoice::GuestWifi => {
            // 1.x validate_ssid + WIFI_* choice gates fire at plan time;
            // the omitted-flag defaults are the valid 1.x defaults.
            // Refuse the psk/sae-without-key foot-gun up front (1.x
            // renders it and hostapd then refuses to start the AP).
            let encryption = args.ap_encryption.clone().unwrap_or_else(|| "psk2".into());
            let key = args.ap_key.clone().unwrap_or_default();
            if key.is_empty() && encryption != "none" && encryption != "owe" {
                return Err(format!(
                    "--ap-encryption {encryption} needs --ap-key \
                     (or pass --ap-encryption none for an open network)"
                ));
            }
            Ok(Profile::GuestWifi(GuestWifiProfile {
                ssid: args.ap_ssid.clone().unwrap_or_else(|| "Guest".into()),
                key,
                encryption,
                band: args.ap_band.clone().unwrap_or_else(|| "2.4ghz".into()),
                isolation: !args.ap_no_isolation,
                ..GuestWifiProfile::default()
            }))
        }
        ProfileChoice::Travelmate => Ok(Profile::Travelmate(TravelmateProfile {
            radio: args.trm_radio.clone().unwrap_or_else(|| "radio0".into()),
            timeout: args.trm_timeout.unwrap_or(60),
            retry: args.trm_retry.unwrap_or(5),
            captive: !args.trm_no_captive,
            ..TravelmateProfile::default()
        })),
        ProfileChoice::Pbr => Ok(Profile::Pbr(PbrProfile {
            wan_interface: args.pbr_wan.clone().unwrap_or_else(|| "wan".into()),
            lan_interface: args.pbr_lan.clone().unwrap_or_else(|| "lan".into()),
            ..PbrProfile::default()
        })),
        ProfileChoice::Mwan3 => Ok(Profile::Mwan3(Mwan3Profile {
            primary: args.mwan3_primary.clone().unwrap_or_else(|| "wan".into()),
            secondary: args
                .mwan3_secondary
                .clone()
                .unwrap_or_else(|| "usbwan".into()),
            policy: args
                .mwan3_policy
                .clone()
                .unwrap_or_else(|| "failover".into()),
            ..Mwan3Profile::default()
        })),
        ProfileChoice::Nodns => Ok(Profile::Nodns(NodnsProfile {
            zone: args
                .nodns_zone
                .clone()
                .unwrap_or_else(|| "nodns.shop".into()),
            api_url: args
                .nodns_api_url
                .clone()
                .unwrap_or_else(|| "https://nodns.shop".into()),
            poll_interval: args.nodns_poll_interval.unwrap_or(300),
        })),
        ProfileChoice::AutoSqm => Ok(Profile::AutoSqm(AutoSqmProfile {
            mode: args.autosqm_mode.clone().unwrap_or_else(|| "static".into()),
            interface: args
                .autosqm_interface
                .clone()
                .unwrap_or_else(|| "wan".into()),
            target_percent: args.autosqm_target_percent.unwrap_or(90),
            ..AutoSqmProfile::default()
        })),
        ProfileChoice::OpenClash => Ok(Profile::OpenClash(OpenClashProfile {
            proxy_type: args
                .openclash_proxy_type
                .clone()
                .unwrap_or_else(|| "ss".into()),
            core_type: args
                .openclash_core_type
                .clone()
                .unwrap_or_else(|| "Meta".into()),
            dns_mode: args
                .openclash_dns_mode
                .clone()
                .unwrap_or_else(|| "redir-host".into()),
        })),
        ProfileChoice::Ssl => Ok(Profile::Ssl(SslProfile {
            provider: args
                .ssl_provider
                .clone()
                .unwrap_or_else(|| "lancert".into()),
            enable_uhttpd_https: !args.ssl_no_uhttpd_https,
            open_port_443_nds: !args.ssl_no_443_nds,
        })),
        ProfileChoice::VpnPia => {
            let (username, password) = match (args.pia_username.clone(), args.pia_password.clone())
            {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    return Err("--pia-username and --pia-password are required for vpn-pia".into());
                }
            };
            let gateway = args.pia_gateway.clone().unwrap_or_default();
            if gateway.is_empty() {
                return Err(
                    "--pia-gateway is required for vpn-pia (the circular-routing pin)".into(),
                );
            }
            Ok(Profile::VpnPia(VpnPiaProfile {
                username,
                password,
                region: args
                    .pia_region
                    .clone()
                    .unwrap_or_else(|| "netherlands".into()),
                upstream_gateway: gateway,
                upstream_iface: args.pia_iface.clone().unwrap_or_else(|| "wwan".into()),
                kill_switch: !args.pia_no_kill_switch,
                allow_management: !args.pia_no_management,
            }))
        }
        ProfileChoice::VpnNordvpnOpenvpn => {
            let (username, password, station, hostname) = match (
                args.nordovpn_username.clone(),
                args.nordovpn_password.clone(),
                args.nordovpn_station.clone(),
                args.nordovpn_hostname.clone(),
            ) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => {
                    return Err(
                        "--nordovpn-username, --nordovpn-password, --nordovpn-station and \
                         --nordovpn-hostname are required for vpn-nordvpn-openvpn (resolve them \
                         on the host with 1.x `python3 scripts/nordvpn.py config --token TOKEN`)"
                            .into(),
                    );
                }
            };
            Ok(Profile::VpnNordvpnOpenvpn(VpnNordvpnOpenvpnProfile {
                username,
                password,
                station,
                hostname,
                proto: args.nordovpn_proto.clone().unwrap_or_else(|| "udp".into()),
                cipher: args
                    .nordovpn_cipher
                    .clone()
                    .unwrap_or_else(|| "AES-256-CBC".into()),
                kill_switch: !args.nordovpn_no_kill_switch,
                allow_management: !args.nordovpn_no_management,
            }))
        }
        ProfileChoice::VpnNordvpn => {
            let (private_key, server_public_key, endpoint_host, route_target) =
                match (
                    args.nord_private_key.clone(),
                    args.nord_server_public_key.clone(),
                    args.nord_endpoint_host.clone(),
                    args.nord_route_target.clone(),
                ) {
                    (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                    _ => return Err(
                        "--nord-private-key, --nord-server-public-key, --nord-endpoint-host and \
                         --nord-route-target are required for vpn-nordvpn (resolve them on the \
                         host with 1.x `python3 scripts/nordvpn.py config --token TOKEN`)"
                            .into(),
                    ),
                };
            Ok(Profile::VpnNordvpn(VpnNordvpnProfile {
                private_key,
                server_public_key,
                endpoint_host,
                route_target,
                endpoint_port: args
                    .nord_endpoint_port
                    .clone()
                    .unwrap_or_else(|| "51820".into()),
                upstream_gateway: args.nord_gateway.clone().unwrap_or_default(),
                upstream_iface: args.nord_iface.clone().unwrap_or_else(|| "wwan".into()),
                kill_switch: !args.nord_no_kill_switch,
                allow_management: !args.nord_no_management,
                ..VpnNordvpnProfile::default()
            }))
        }
        ProfileChoice::VpnPiaOpenvpn => {
            let (username, password) = match (
                args.pia_ovpn_username.clone(),
                args.pia_ovpn_password.clone(),
            ) {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    return Err(
                        "--pia-ovpn-username and --pia-ovpn-password are required for \
                         vpn-pia-openvpn"
                            .into(),
                    );
                }
            };
            Ok(Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
                username,
                password,
                port: args.pia_ovpn_port.clone().unwrap_or_else(|| "8080".into()),
                upstream_gateway: args.pia_ovpn_gateway.clone().unwrap_or_default(),
                upstream_iface: args.pia_ovpn_iface.clone().unwrap_or_else(|| "wan".into()),
                kill_switch: !args.pia_ovpn_no_kill_switch,
                allow_management: !args.pia_ovpn_no_management,
                ..VpnPiaOpenvpnProfile::default()
            }))
        }
        ProfileChoice::CashuVpnClient => {
            let (peer_public_key, peer_ip, server_host) = match (
                args.peer_public_key.clone(),
                args.peer_ip.clone(),
                args.endpoint_host.clone(),
            ) {
                (Some(k), Some(ip), Some(h)) => (k, ip, h),
                _ => {
                    return Err(
                        "--peer-public-key, --endpoint-host and --peer-ip are required for \
                         cashu-vpn-client"
                            .into(),
                    );
                }
            };
            Ok(Profile::CashuVpnClient(CashuVpnClientProfile {
                peer_public_key,
                peer_ip,
                server_host,
                server_port: args.endpoint_port.unwrap_or(51820),
                allowed_ips: args
                    .allowed_ips
                    .clone()
                    .unwrap_or_else(|| "0.0.0.0/0".into()),
                dns: args.dns.clone().unwrap_or_else(|| "1.1.1.1".into()),
                kill_switch: !args.no_kill_switch,
                ..CashuVpnClientProfile::default()
            }))
        }
        ProfileChoice::MptcpBonding => {
            // all three credentials come from `bsbf-add-client` on the
            // VPS — no sane defaults; charset/format gates fire at plan
            // time (MptcpBondingProfile::validate)
            Ok(Profile::MptcpBonding(MptcpBondingProfile {
                server_ipv4: args.mptcp_server_ipv4.clone().unwrap_or_default(),
                server_port: args.mptcp_server_port.unwrap_or(0),
                uuid: args.mptcp_uuid.clone().unwrap_or_default(),
            }))
        }
        ProfileChoice::Tollgate => Ok(Profile::Tollgate(TollgateProfile {
            gateway_name: args.tollgate_gateway_name.clone().unwrap_or_default(),
            gateway_domain: args.tollgate_gateway_domain.clone().unwrap_or_default(),
            clientid: args
                .tollgate_clientid
                .clone()
                .unwrap_or_else(|| "mac".into()),
            allow_lan_ssh: args.tollgate_allow_lan_ssh,
            install_hotplug: !args.tollgate_no_hotplug,
            hotplug_interface: args
                .tollgate_hotplug_interface
                .clone()
                .unwrap_or_else(|| "wwan".into()),
            mint_url: args.tollgate_mint_url.clone().unwrap_or_default(),
            lightning_address: args.tollgate_lightning_address.clone().unwrap_or_default(),
            price_per_minute: args.tollgate_price_per_minute.unwrap_or(1),
            price_sats_per_mib: args.tollgate_price_sats_per_mib.unwrap_or(0),
            upstream_usd_per_gb: args
                .tollgate_upstream_usd_per_gb
                .clone()
                .unwrap_or_else(|| "0".into()),
            markup: args.tollgate_markup.clone().unwrap_or_else(|| "2.0".into()),
            fx_sats_per_usd: args.tollgate_fx_sats_per_usd.unwrap_or(0),
        })),
        ProfileChoice::TollgateSecurity => Ok(Profile::TollgateSecurity(TollgateSecurityProfile)),
    }
}

fn cmd_discover_v6(interface: &str, mac: Option<&str>, ports: &[u16]) -> ExitCode {
    use conwrt_local_std::v6;

    println!("=== probe-host self-check ({}):", interface);
    let check = v6::self_check(interface);
    println!(
        "  exists={} carrier={:?} ipv6_disabled={:?} link_local={}",
        check.exists,
        check.carrier,
        check.ipv6_disabled,
        check
            .link_local
            .map(|a| a.to_string())
            .unwrap_or_else(|| "none".into())
    );
    for problem in check.problems() {
        println!("  !! {problem}");
    }
    if !check.ready() {
        println!("\nfix the problems above first — the prober itself cannot speak v6.");
    }
    println!("\n=== soliciting router advertisement (rdisc6):");
    match v6::solicit_router_advertisement(interface, 2) {
        Ok(Some(ra)) => {
            println!(
                "  router mac      : {:?}",
                ra.router_mac.map(|m| m.to_string())
            );
            println!(
                "  router link-local: {}",
                ra.router_link_local
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into())
            );
            println!("  prefixes        : {:?}", ra.prefixes);
            println!("  dns             : {:?}", ra.dns_servers);
            println!(
                "  stateful addr/other: {}/{}",
                ra.stateful_address, ra.stateful_other
            );
            println!("  mtu             : {:?}", ra.mtu);
            println!("\n  ready commands:");
            for cmd in ra.commands(interface) {
                println!("    {cmd}");
            }
            if let (Some(ll), Some(idx)) = (ra.router_link_local, v6::interface_index(interface)) {
                for port in ports {
                    if let Some(banner) =
                        v6::banner_probe_v6(ll, idx, *port, std::time::Duration::from_secs(3))
                    {
                        println!("    :{port} banner: {banner:?}");
                    }
                }
            }
        }
        Ok(None) => {
            println!("  no router answered — try --mac for EUI-64 derivation without an RA")
        }
        Err(e) => println!("  {e}"),
    }
    if let Some(mac_str) = mac {
        match conwrt_types::MacAddress::parse(mac_str) {
            Ok(mac) => {
                let ll = v6::derive_eui64_link_local(&mac);
                println!("\n=== EUI-64 for {mac}: {ll}");
                if let Some(idx) = v6::interface_index(interface) {
                    for port in ports {
                        match v6::banner_probe_v6(ll, idx, *port, std::time::Duration::from_secs(3))
                        {
                            Some(banner) => println!("    :{port} banner: {banner:?}"),
                            None => println!("    :{port} no answer"),
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    }
    ExitCode::SUCCESS
}

fn cmd_maas(command: MaasCommand) -> ExitCode {
    match command {
        MaasCommand::Flash {
            image,
            sha256,
            target,
            user_data,
            meta_data,
            network_config,
            serial_whitelist,
        } => cmd_maas_flash(
            &image,
            &sha256,
            &target,
            user_data,
            meta_data,
            network_config,
            serial_whitelist,
        ),
        MaasCommand::Vm { command } => cmd_maas_vm(command),
    }
}

fn cmd_maas_flash(
    image_path: &Path,
    sha256: &str,
    target: &Path,
    user_data: Option<PathBuf>,
    meta_data: Option<PathBuf>,
    network_config: Option<PathBuf>,
    serial_whitelist: Option<Vec<String>>,
) -> ExitCode {
    use conwrt_local_std::block::FileBlockWriter;
    use conwrt_maas::flash::{CloudInitSeed, DiskFlashPlan, Sha256, execute_flash};
    use std::str::FromStr;

    let image = match std::fs::read(image_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read image {}: {e}", image_path.display());
            return ExitCode::from(2);
        }
    };
    let digest = match Sha256::from_str(sha256) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("--sha256: {e}");
            return ExitCode::from(2);
        }
    };
    // #305: the documented MAAS artifact is *.img.xz — verify the
    // ARCHIVE checksum against --sha256, then flash the DECOMPRESSED
    // image (the Python original's xzcat flow). Writing the archive
    // bytes verbatim leaves the disk starting with an XZ stream.
    let published_sha = sha256;
    const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
    let (image, digest) = if image.starts_with(XZ_MAGIC) {
        if Sha256::hash(&image) != digest {
            eprintln!(
                "archive checksum mismatch: refusing to decompress or write {}",
                image_path.display()
            );
            return ExitCode::from(2);
        }
        let mut decompressed = Vec::new();
        use std::io::Read;
        if let Err(e) = xz2::read::XzDecoder::new(&image[..]).read_to_end(&mut decompressed) {
            eprintln!("cannot decompress {}: {e}", image_path.display());
            return ExitCode::from(2);
        }
        let decompressed_sha = Sha256::hash(&decompressed);
        (decompressed, decompressed_sha)
    } else {
        (image, digest)
    };
    let had_network_config = network_config.is_some();
    let mut plan = DiskFlashPlan::new(digest);
    if let (Some(ud_path), Some(md_path)) = (&user_data, &meta_data) {
        let user_data = match std::fs::read_to_string(ud_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read user-data {}: {e}", ud_path.display());
                return ExitCode::from(2);
            }
        };
        let meta_data = match std::fs::read_to_string(md_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read meta-data {}: {e}", md_path.display());
                return ExitCode::from(2);
            }
        };
        let network_config = match network_config {
            Some(p) => match std::fs::read_to_string(&p) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("cannot read network-config {}: {e}", p.display());
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
        plan = plan.with_seed(CloudInitSeed {
            user_data,
            meta_data,
            network_config,
        });
    }

    // Specimen gate (AGENTS.md MAC/serial rule, #302): block-device
    // targets need identity evidence — an explicit serial whitelist is
    // REQUIRED (an unnamed "any USB disk" pass is a wrong-unit flash) —
    // and the verified device is opened read+write immediately so the
    // destructive write goes through the pinned inode, not a later
    // re-resolution of the /dev/sdX name. Regular files (CI, lab
    // staging) pass through.
    let is_device = match std::fs::metadata(target) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            meta.file_type().is_block_device()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            eprintln!("cannot stat target {}: {e}", target.display());
            return ExitCode::from(2);
        }
    };
    let mut writer = if is_device {
        let whitelist = serial_whitelist.as_deref().unwrap_or(&[]);
        if whitelist.is_empty() {
            eprintln!(
                "flash refused: block-device targets require --serial-whitelist \
                 (specimen gate, AGENTS.md serial rule)"
            );
            return ExitCode::from(2);
        }
        match conwrt_local_std::specimen::verify_disk(target, whitelist) {
            Ok(id) => println!(
                "verified:  {} usb serial={} {}GB rw",
                target.display(),
                id.serial.as_deref().unwrap_or("?"),
                id.size_bytes.unwrap_or(0) / 1_000_000_000
            ),
            Err(msg) => {
                eprintln!("flash refused: {msg}");
                return ExitCode::from(2);
            }
        }
        match FileBlockWriter::open_device(target) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("cannot pin target {}: {e}", target.display());
                return ExitCode::from(2);
            }
        }
    } else {
        FileBlockWriter::new(target)
    };
    match pollster::block_on(execute_flash(&plan, &image, &mut writer)) {
        Ok(report) => {
            println!("image:     {}", image_path.display());
            println!("sha256:    {published_sha} (verified before write)");
            println!("target:    {}", target.display());
            println!(
                "written:   {} bytes (read-back verified)",
                report.bytes_written
            );
            if report.seed_staged {
                println!(
                    "seed:      staged at {}.seed/ (user-data, meta-data{})",
                    target.display(),
                    if had_network_config {
                        ", network-config"
                    } else {
                        ""
                    }
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("flash refused: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Real clock for provider polling (tokio sleep — the CLI owns a runtime).
struct RealTime;

impl conwrt_core::Time for RealTime {
    async fn sleep_ms(&mut self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

fn maas_runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("cannot start async runtime: {e}");
        ExitCode::from(2)
    })
}

fn cmd_maas_vm(command: VmCommand) -> ExitCode {
    use conwrt_local_std::maas::HttpMaasClient;
    use conwrt_maas::provider::{ComputeProvider, MaasProvider, VmSpec};

    let rt = match maas_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    fn http_client(region: &str, vm_host: &str) -> Result<HttpMaasClient, ExitCode> {
        let mut client = HttpMaasClient::new(region, vm_host).map_err(|e| {
            eprintln!("{e}");
            ExitCode::from(2)
        })?;
        if let Ok(key) = std::env::var("CONWRT_MAAS_AUTH") {
            client = match client.with_api_key(&key) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return Err(ExitCode::from(2));
                }
            };
            // RFC 5849 §3.4.4: PLAINTEXT credentials need TLS; the
            // opt-in exists for isolated http lab regions only.
            if std::env::var("CONWRT_MAAS_INSECURE_HTTP").ok().as_deref() == Some("1") {
                client = client.allow_insecure_http();
            }
        }
        Ok(client)
    }

    match command {
        VmCommand::Create {
            name,
            cores,
            memory_mib,
            disk_gib,
            region,
            vm_host,
            poll_ms,
            max_polls,
        } => {
            let spec = VmSpec {
                name,
                cores,
                memory_mib,
                disk_gib,
            };
            let client = match http_client(&region, &vm_host) {
                Ok(c) => c,
                Err(code) => return code,
            };
            let mut provider = MaasProvider::new(client, RealTime).with_polling(poll_ms, max_polls);
            match rt.block_on(provider.create_vm(&spec)) {
                Ok(vm) => {
                    println!("created:   {} ({})", vm.system_id, vm.hostname);
                    println!("state:     {}", vm.state);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("create failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        VmCommand::List { region } => {
            let mut provider = MaasProvider::new(
                {
                    match http_client(&region, "unused") {
                        Ok(c) => c,
                        Err(code) => return code,
                    }
                },
                RealTime,
            );
            match rt.block_on(provider.list_vms()) {
                Ok(vms) => {
                    if vms.is_empty() {
                        println!("no machines");
                    }
                    for vm in vms {
                        println!("{:<10} {:<20} {}", vm.system_id, vm.hostname, vm.state);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("list failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        VmCommand::Describe { system_id, region } => {
            let mut provider = MaasProvider::new(
                {
                    match http_client(&region, "unused") {
                        Ok(c) => c,
                        Err(code) => return code,
                    }
                },
                RealTime,
            );
            match rt.block_on(provider.describe_vm(&system_id)) {
                Ok(vm) => {
                    println!("system_id: {}", vm.system_id);
                    println!("hostname:  {}", vm.hostname);
                    println!("state:     {}", vm.state);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("describe failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        VmCommand::Destroy { system_id, region } => {
            let mut provider = MaasProvider::new(
                {
                    match http_client(&region, "unused") {
                        Ok(c) => c,
                        Err(code) => return code,
                    }
                },
                RealTime,
            );
            match rt.block_on(provider.destroy_vm(&system_id)) {
                Ok(()) => {
                    println!("destroyed: {system_id} (released and deleted)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("destroy failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn cmd_cache(command: CacheCommand) -> ExitCode {
    match command {
        CacheCommand::List { images_root } => cache_list(&images_root),
        CacheCommand::Clean {
            model_id,
            keep_latest,
            yes,
            images_root,
        } => cache_clean(&model_id, keep_latest, yes, &images_root),
    }
}

fn cache_list(images_root: &Path) -> ExitCode {
    let Ok(model_dirs) = std::fs::read_dir(images_root) else {
        eprintln!("No images/ directory found.");
        return ExitCode::from(1);
    };
    let mut rows: Vec<(String, String, String, String, u64)> = Vec::new();
    let mut model_dirs: Vec<_> = model_dirs.filter_map(|e| e.ok()).collect();
    model_dirs.sort_by_key(|e| e.file_name());
    for model_dir in model_dirs {
        if !model_dir.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }
        let Ok(hash_dirs) = std::fs::read_dir(model_dir.path()) else {
            continue;
        };
        let mut hash_dirs: Vec<_> = hash_dirs.filter_map(|e| e.ok()).collect();
        hash_dirs.sort_by_key(|e| e.file_name());
        for hash_dir in hash_dirs {
            if !hash_dir.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                continue;
            }
            let dir = hash_dir.path();
            let mut version = "?".to_string();
            let mut code = String::new();
            let mut types: Vec<&str> = Vec::new();
            let mut total = 0u64;
            let Ok(files) = std::fs::read_dir(&dir) else {
                continue;
            };
            for file in files.filter_map(|e| e.ok()) {
                let name = file.file_name().to_string_lossy().into_owned();
                let Ok(meta) = file.metadata() else {
                    continue;
                };
                if name.ends_with(".metadata.json") {
                    if let Ok(text) = std::fs::read_to_string(file.path()) {
                        if let Ok(value) = serde_json_parse(&text) {
                            version = value
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string();
                            code = value
                                .get("version_code")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .chars()
                                .take(20)
                                .collect();
                        }
                    }
                } else if name.ends_with(".bin") && meta.is_file() {
                    total += meta.len();
                    let kind = if name.contains("sysupgrade") {
                        "sysupgrade"
                    } else if name.contains("recovery") {
                        "recovery"
                    } else if name.contains("factory") {
                        "factory"
                    } else {
                        "other"
                    };
                    types.push(kind);
                }
            }
            if !code.is_empty() {
                version.push_str(&format!(" ({code})"));
            }
            types.sort_unstable();
            types.dedup();
            rows.push((
                model_dir.file_name().to_string_lossy().into_owned(),
                hash_dir.file_name().to_string_lossy().into_owned(),
                version,
                if types.is_empty() {
                    "none".to_string()
                } else {
                    types.join(", ")
                },
                total,
            ));
        }
    }
    if rows.is_empty() {
        println!("No cached firmware images found.");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<30}  {:<14}  {:<35}  {:<30}  {:>8}",
        "Model", "Hash", "Version", "Types", "Size"
    );
    println!("{}", "-".repeat(130));
    for (model, hash, version, types, total) in &rows {
        let hash: String = hash.chars().take(12).collect();
        println!(
            "{:<30}  {:<14}  {:<35}  {:<30}  {:>7.1} MB",
            model,
            hash,
            version,
            types,
            *total as f64 / 1024.0 / 1024.0
        );
    }
    println!("\nTotal: {} cached build(s)", rows.len());
    ExitCode::SUCCESS
}

/// Minimal `serde_json::Value` parse without naming the crate at the
/// call sites (conwrt-cli has no direct serde_json dependency).
fn serde_json_parse(text: &str) -> Result<serde_json::Value, ()> {
    serde_json::from_str(text).map_err(|_| ())
}

fn cache_clean(
    model_id: &Option<String>,
    keep_latest: bool,
    yes: bool,
    images_root: &Path,
) -> ExitCode {
    use conwrt_image::clean::{CleanOptions, clean_cache, plan_cache_clean};

    let options = CleanOptions {
        keep_latest,
        profile: model_id.clone(),
    };
    let plan = match plan_cache_clean(images_root, &options) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("cache clean failed: {e}");
            return ExitCode::from(1);
        }
    };
    if plan.removed.is_empty() {
        match model_id {
            Some(id) => println!("No cached images found for model '{id}'."),
            None => println!("No cached images found."),
        }
        return ExitCode::SUCCESS;
    }
    println!(
        "Would remove {} cached build(s) ({:.1} MB):",
        plan.removed.len(),
        plan.freed_bytes as f64 / 1024.0 / 1024.0
    );
    for dir in &plan.removed {
        let model = dir
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let hash: String = dir
            .file_name()
            .map(|n| n.to_string_lossy().chars().take(12).collect())
            .unwrap_or_default();
        println!("  {model}/{hash}...");
    }
    if !yes {
        println!("\n(dry run — re-run with --yes to remove)");
        return ExitCode::SUCCESS;
    }
    match clean_cache(images_root, &options) {
        Ok(report) => {
            println!(
                "Removed {} cached build(s), freed {:.1} MB",
                report.removed.len(),
                report.freed_bytes as f64 / 1024.0 / 1024.0
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cache clean failed: {e}");
            ExitCode::from(1)
        }
    }
}

struct SourceImageArgs<'a> {
    model_id: &'a str,
    release: Option<&'a str>,
    image_suffix: Option<&'a str>,
    images_root: &'a Path,
    downloads_base: Option<&'a str>,
    no_verify: bool,
    force: bool,
}

fn cmd_source_image(args: &SourceImageArgs<'_>, dir: &Path) -> ExitCode {
    use conwrt_image::downloads::{FetchOptions, ReqwestDownloadsClient, fetch_image};
    use conwrt_image::vanilla::{ReleaseOverrides, SuffixOverrides, VanillaModel};

    let (registry, _) = load_registry(dir);
    let Some(model) = registry.models().iter().find(|m| m.id == args.model_id) else {
        eprintln!("unknown model id {:?} (see `conwrt models`)", args.model_id);
        return ExitCode::from(2);
    };
    let openwrt_str = |key: &str| {
        model
            .openwrt
            .extras
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    let vanilla_model = VanillaModel {
        id: model.id.clone(),
        target: model.openwrt.target.clone(),
        profile: model.openwrt.profile.clone(),
        release: openwrt_str("release"),
        image_suffix: openwrt_str("image_suffix"),
    };
    let client = match args
        .downloads_base
        .map(ReqwestDownloadsClient::with_base)
        .unwrap_or_else(ReqwestDownloadsClient::new)
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("cannot start downloads client: {e}");
            return ExitCode::from(2);
        }
    };
    let env_release = std::env::var("CONWRT_OPENWRT_RELEASE").ok();
    let env_suffix = std::env::var("CONWRT_IMAGE_SUFFIX").ok();
    let options = FetchOptions {
        release: ReleaseOverrides {
            cli: args.release,
            env: env_release.as_deref(),
        },
        suffix: SuffixOverrides {
            cli: args.image_suffix,
            env: env_suffix.as_deref(),
        },
        verify: !args.no_verify,
        force: args.force,
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(fetch_image(
        &client,
        args.images_root,
        &vanilla_model,
        &options,
    )) {
        Ok(fetched) => {
            println!("URL:     {}", fetched.url);
            if fetched.already_cached {
                println!("cached:  {}", fetched.path.display());
            } else if let Some(sha) = &fetched.sha256 {
                println!("SHA-256 verified: {sha}");
            }
            println!("Image ready: {}", fetched.path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("source-image failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_image(
    model_id: &str,
    release: Option<&str>,
    packages: &[String],
    defaults: Option<&Path>,
    images_root: &Path,
    asu_base: Option<&str>,
    dir: &Path,
) -> ExitCode {
    use conwrt_image::client::PollConfig;
    use conwrt_image::http::ReqwestAsuClient;
    use conwrt_image::types::BuildRequest;
    use conwrt_image::workflow::request_and_cache;

    let (registry, _) = load_registry(dir);
    let Some(model) = registry.models().iter().find(|m| m.id == model_id) else {
        eprintln!("unknown model id {model_id:?} (see `conwrt models`)");
        return ExitCode::from(2);
    };
    let version = release
        .map(str::to_string)
        .unwrap_or_else(|| model.openwrt.version.clone());
    let packages = if packages.is_empty() {
        None
    } else {
        Some(packages.to_vec())
    };
    let defaults_script = defaults.map(|p| {
        let text = std::fs::read_to_string(p)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        if let Err(e) = conwrt_image::types::validate_defaults_script(&text) {
            eprintln!("defaults rejected: {e}");
            std::process::exit(2);
        }
        text
    });
    let mut request = BuildRequest::openwrt(
        version,
        model.openwrt.target.clone(),
        model.openwrt.profile.clone(),
    );
    request.packages = packages;
    request.defaults = defaults_script;

    let client = match asu_base.map(conwrt_image::client::AsuEndpoints::from_base) {
        Some(e) => ReqwestAsuClient::with_endpoints(e).expect("ASU client"),
        None => ReqwestAsuClient::new().expect("ASU client"),
    };
    // Tests and private instances want fast polls; the default keeps
    // firmware-manager.py parity (10 s flat).
    let poll = match std::env::var("CONWRT_ASU_POLL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(ms) => PollConfig {
            initial_interval: std::time::Duration::from_millis(ms),
            max_interval: std::time::Duration::from_millis(ms),
            ..PollConfig::default()
        },
        None => PollConfig::default(),
    };
    println!(
        "request: {} {} for {}",
        request.distro, request.version, model.id
    );
    if let Some(pkgs) = &request.packages {
        println!("packages ({})", pkgs.len());
    }
    if request.defaults.is_some() {
        println!("defaults: first-boot script attached");
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(request_and_cache(
        &client,
        images_root,
        &request,
        &poll,
        &Default::default(),
    )) {
        Ok(outcome) => {
            if outcome.already_cached {
                println!("cached:  {} (short-circuit)", outcome.cache_dir.display());
            } else {
                println!("built:   {}", outcome.cache_dir.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("image request failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_agent(command: AgentCommand) -> ExitCode {
    use conwrt_agent_proto::controller::AgentClient;
    use conwrt_agent_proto::protocol::DisconnectPolicy;

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::from(2);
        }
    };

    match command {
        AgentCommand::Info { addr } => {
            let caps = rt.block_on(async {
                let mut client = AgentClient::connect(&addr).await?;
                client.handshake("conwrt-cli").await
            });
            match caps {
                Ok(caps) => {
                    println!("connected to {addr}");
                    println!("capabilities ({}):", caps.len());
                    for c in &caps {
                        let detail = if c.detail.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " [{}]",
                                c.detail
                                    .iter()
                                    .map(|(k, v)| format!("{k}={v}"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        };
                        println!("  {}{}", c.name, detail);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("agent error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        AgentCommand::Lease {
            addr,
            resource,
            shared,
            controller,
        } => {
            // #378: the lease is held for the process lifetime — a
            // heartbeat loop keeps it alive and Ctrl-C releases it. An
            // acquired-then-abandoned lease pins the resource until
            // agent restart.
            let controller_id = controller.unwrap_or_else(|| "conwrt-cli".to_string());
            let result: Result<conwrt_agent_proto::protocol::LeaseResponse, _> =
                rt.block_on(async {
                let mut client = AgentClient::connect(&addr).await?;
                client.handshake(&controller_id).await?;
                let resp = client
                    .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
                        resource,
                        exclusive: !shared,
                        on_disconnect: DisconnectPolicy::Abort,
                    })
                    .await?;
                let conwrt_agent_proto::protocol::LeaseResponse::Granted {
                    lease_id,
                    heartbeat_ms,
                } = resp
                else {
                    return Ok::<_, conwrt_agent_proto::controller::ClientError>(resp);
                };
                println!(
                    "lease {lease_id} granted (heartbeat every {heartbeat_ms}ms; Ctrl-C to release)"
                );
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(
                            heartbeat_ms.into(),
                        )) => {
                            client.heartbeat(lease_id).await?;
                        }
                        _ = tokio::signal::ctrl_c() => {
                            let released = client.release_lease(lease_id).await?;
                            if released {
                                println!("lease {lease_id} released");
                            } else {
                                eprintln!("lease {lease_id} was already gone");
                            }
                            break;
                        }
                    }
                }
                Ok(conwrt_agent_proto::protocol::LeaseResponse::Granted {
                    lease_id,
                    heartbeat_ms,
                })
            });
            match result {
                Ok(conwrt_agent_proto::protocol::LeaseResponse::Granted { .. }) => {
                    ExitCode::SUCCESS
                }
                Ok(conwrt_agent_proto::protocol::LeaseResponse::Denied { holder }) => {
                    eprintln!("denied (holder: {holder:?})");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("agent error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        AgentCommand::Status { addr, transfer_id } => {
            let result = rt.block_on(async {
                let mut client = AgentClient::connect(&addr).await?;
                client.handshake("conwrt-cli").await?;
                client.stream_status(transfer_id).await
            });
            match result {
                Ok(ack) => {
                    // Offset and state are separate fields: the old
                    // "{contiguous}/{state} bytes" printed nonsense like
                    // "4096/in progress bytes" (#378).
                    println!(
                        "transfer {transfer_id}: {} bytes (state: {})",
                        ack.contiguous,
                        if ack.done { "done" } else { "in progress" },
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("agent error: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

/// After a successful connection, persist a first-use host key so the
/// trust ladder's changed-key refusal protects *later* invocations
/// (TOFU with a throwaway store accepts any spoofed endpoint once).
fn persist_new_host_key(
    kh_path: &Path,
    addr: &str,
    key: &HostKeyView,
    known_before: &[HostKeyView],
) {
    if known_before.iter().any(|k| k == key) {
        return; // already pinned in the persistent store
    }
    use conwrt_core::ssh::TrustStore;
    let mut store = FileTrustStore::new(kh_path.to_path_buf());
    store.remember(addr, key);
    println!(
        "host key:   {} (first use; recorded in {})",
        key.fingerprint,
        kh_path.display()
    );
}

/// The modeled board name: `/tmp/sysinfo/board_name` reports the
/// `openwrt.board_name` value (e.g. `AAOB`), NOT the image/DTS `device`
/// id — older models without a modeled board name fall back to `device`.
fn board_name_or_device(model: &conwrt_types::DeviceModel) -> &str {
    model
        .openwrt
        .board_name
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .unwrap_or(&model.openwrt.device)
}

/// Live board_name acceptance: the modeled `board_name` when present,
/// with the DTS `device` id accepted as an alias (some builds report
/// the DTS name where board.json uses a short board id).
fn board_matches(model: &conwrt_types::DeviceModel, board: &str) -> bool {
    let modeled = board_name_or_device(model);
    board == modeled
        || board == model.openwrt.device
        || model
            .openwrt
            .board_names
            .as_deref()
            .is_some_and(|names| names.iter().any(|name| name == board))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_args(profile: ProfileChoice) -> ProfileArgs {
        ProfileArgs {
            profile,
            download_kbps: None,
            upload_kbps: None,
            interface: "wan".into(),
            provider: None,
            listen_port: None,
            idle_timeout: None,
            max_auth_tries: None,
            password_auth: false,
            listen_ip: None,
            web_port: None,
            dns_port: None,
            target: None,
            peer_public_key: None,
            endpoint_host: None,
            endpoint_port: None,
            peer_ip: None,
            peer_psk: None,
            address: None,
            dns: None,
            allowed_ips: None,
            no_kill_switch: false,
            subnet: None,
            peer1_public_key: None,
            peer1_allowed_ips: None,
            peer1_psk: None,
            ap_ssid: None,
            ap_key: None,
            ap_encryption: None,
            ap_band: None,
            ap_no_isolation: false,
            pbr_wan: None,
            pbr_lan: None,
            mwan3_primary: None,
            mwan3_secondary: None,
            mwan3_policy: None,
            nodns_zone: None,
            nodns_api_url: None,
            nodns_poll_interval: None,
            autosqm_mode: None,
            autosqm_interface: None,
            autosqm_target_percent: None,
            openclash_proxy_type: None,
            openclash_core_type: None,
            openclash_dns_mode: None,
            ssl_provider: None,
            ssl_no_uhttpd_https: false,
            ssl_no_443_nds: false,
            pia_username: None,
            pia_password: None,
            pia_region: None,
            pia_gateway: None,
            pia_iface: None,
            pia_no_kill_switch: false,
            pia_no_management: false,
            nordovpn_username: None,
            nordovpn_password: None,
            nordovpn_station: None,
            nordovpn_hostname: None,
            nordovpn_proto: None,
            nordovpn_cipher: None,
            nordovpn_no_kill_switch: false,
            nordovpn_no_management: false,
            nord_private_key: None,
            nord_server_public_key: None,
            nord_endpoint_host: None,
            nord_route_target: None,
            nord_endpoint_port: None,
            nord_gateway: None,
            nord_iface: None,
            nord_no_kill_switch: false,
            nord_no_management: false,
            pia_ovpn_username: None,
            pia_ovpn_password: None,
            pia_ovpn_port: None,
            pia_ovpn_gateway: None,
            pia_ovpn_iface: None,
            pia_ovpn_no_kill_switch: false,
            pia_ovpn_no_management: false,
            mptcp_server_ipv4: None,
            mptcp_server_port: None,
            mptcp_uuid: None,
            tollgate_gateway_name: None,
            tollgate_gateway_domain: None,
            tollgate_clientid: None,
            tollgate_allow_lan_ssh: false,
            tollgate_no_hotplug: false,
            tollgate_hotplug_interface: None,
            tollgate_mint_url: None,
            tollgate_lightning_address: None,
            tollgate_price_per_minute: None,
            tollgate_price_sats_per_mib: None,
            tollgate_upstream_usd_per_gb: None,
            tollgate_markup: None,
            tollgate_fx_sats_per_usd: None,
            trm_radio: None,
            trm_timeout: None,
            trm_retry: None,
            trm_no_captive: false,
        }
    }

    #[test]
    fn build_profile_mptcp_bonding_gates_credentials_at_plan_time() {
        let mut args = profile_args(ProfileChoice::MptcpBonding);
        // no flags: profile builds empty, plan time refuses (1.x required gates)
        let Profile::MptcpBonding(mp) = &build_profile(&args).expect("mptcp builds") else {
            panic!("mptcp profile");
        };
        assert!(mp.server_ipv4.is_empty() && mp.server_port == 0 && mp.uuid.is_empty());
        assert!(matches!(
            mp.validate(),
            Err(conwrt_core::plan::Unsupported::InvalidParams(_))
        ));

        args.mptcp_server_ipv4 = Some("203.0.113.7".into());
        args.mptcp_server_port = Some(16384);
        args.mptcp_uuid = Some("0f0e0d0c-0b0a-4909-8807-060504030201".into());
        let Profile::MptcpBonding(mp) = &build_profile(&args).expect("mptcp builds") else {
            panic!("mptcp profile");
        };
        assert_eq!(mp.server_port, 16384);
        assert_eq!(mp.server_ipv4, "203.0.113.7");
        assert!(mp.validate().is_ok());
    }

    #[test]
    fn build_profile_tollgate_defaults_and_pricing_gate() {
        let Profile::Tollgate(tg) =
            &build_profile(&profile_args(ProfileChoice::Tollgate)).expect("tollgate builds")
        else {
            panic!("tollgate profile");
        };
        // 1.x defaults ride omitted flags; validate passes (no derivation)
        assert_eq!(
            (tg.clientid.as_str(), tg.hotplug_interface.as_str()),
            ("mac", "wwan")
        );
        assert!(tg.install_hotplug && !tg.allow_lan_ssh);
        assert!(tg.validate().is_ok());

        // derivation without an explicit fx rate refuses at plan time
        // (the I/O-free planner purity delta)
        let mut args = profile_args(ProfileChoice::Tollgate);
        args.tollgate_upstream_usd_per_gb = Some("0.83".into());
        let Profile::Tollgate(deriving) = &build_profile(&args).expect("tollgate builds") else {
            panic!("tollgate profile");
        };
        assert!(matches!(
            deriving.validate(),
            Err(conwrt_core::plan::Unsupported::InvalidParams(_))
        ));

        // wifi capability gate on the security profile
        assert_eq!(
            build_profile(&profile_args(ProfileChoice::TollgateSecurity))
                .expect("security builds")
                .requires(),
            &["wifi"]
        );
    }

    #[test]
    fn build_profile_new_arms_default_to_1x_shapes() {
        let ssh = build_profile(&profile_args(ProfileChoice::SshHardening)).expect("ssh");
        let Profile::SshHardening(sh) = &ssh else {
            panic!("ssh profile");
        };
        assert!(sh.disable_password_auth);
        assert_eq!((sh.idle_timeout, sh.max_auth_tries, sh.port), (300, 3, 22));

        let mut cashu_args = profile_args(ProfileChoice::CashuVpnClient);
        cashu_args.peer_public_key = Some("EXITKEY".into());
        cashu_args.peer_ip = Some("10.66.42.2/32".into());
        cashu_args.endpoint_host = Some("vpn.example.com".into());
        let cashu = build_profile(&cashu_args).expect("cashu-vpn-client");
        let Profile::CashuVpnClient(c) = &cashu else {
            panic!("cashu-vpn-client profile");
        };
        assert_eq!(c.peer_ip, "10.66.42.2/32");
        assert_eq!(
            (c.server_host.as_str(), c.server_port),
            ("vpn.example.com", 51820)
        );
        assert_eq!(c.allowed_ips, "0.0.0.0/0");
        assert_eq!(c.dns, "1.1.1.1");
        assert!(c.kill_switch);

        let missing = build_profile(&profile_args(ProfileChoice::CashuVpnClient));
        assert!(missing.is_err(), "required params must be enforced");

        let ag = build_profile(&profile_args(ProfileChoice::Adguard)).expect("adguard");
        let Profile::Adguard(ag) = &ag else {
            panic!("adguard profile");
        };
        assert_eq!(
            (ag.listen_ip.as_str(), ag.web_port, ag.dns_port),
            ("0.0.0.0", 3000, 5353)
        );

        let wd = build_profile(&profile_args(ProfileChoice::RescueWatchdog)).expect("watchdog");
        let Profile::RescueWatchdog(wd) = &wd else {
            panic!("watchdog profile");
        };
        assert_eq!(wd.target, "192.168.1.254");

        let mut wg_args = profile_args(ProfileChoice::WireguardClient);
        wg_args.peer_public_key = Some("SERVERKEY".into());
        wg_args.endpoint_host = Some("vpn.example.com".into());
        let wg = build_profile(&wg_args).expect("wireguard");
        let Profile::WireguardClient(wg) = &wg else {
            panic!("wireguard profile");
        };
        assert_eq!(wg.peer_public_key, "SERVERKEY");
        assert_eq!(wg.endpoint_host, "vpn.example.com");
        assert_eq!(wg.endpoint_port, 51820);
        // 1.x default holds without any flag (Codex #442 P1-1)
        assert!(wg.kill_switch);
        wg_args.no_kill_switch = true;
        let Profile::WireguardClient(off) = &build_profile(&wg_args).expect("wireguard") else {
            panic!("wireguard profile");
        };
        assert!(!off.kill_switch);
        assert!(wg.validate().is_ok());

        let wgs = build_profile(&profile_args(ProfileChoice::WireguardServer)).expect("wg-server");
        let Profile::WireguardServer(wgs) = &wgs else {
            panic!("wg-server profile");
        };
        assert_eq!(
            (
                wgs.listen_port,
                wgs.subnet.as_str(),
                wgs.peer1_allowed_ips.as_str()
            ),
            (51820, "10.1.99.1/24", "10.1.99.2/32")
        );
        assert!(wgs.peer1_public_key.is_empty());

        let mut gw_args = profile_args(ProfileChoice::GuestWifi);
        gw_args.ap_key = Some("guestpass".into());
        let gw = build_profile(&gw_args).expect("guest-wifi");
        let Profile::GuestWifi(gw) = &gw else {
            panic!("guest-wifi profile");
        };
        assert_eq!(
            (gw.ssid.as_str(), gw.encryption.as_str(), gw.band.as_str()),
            ("Guest", "psk2", "2.4ghz")
        );
        assert!(gw.isolation);
        // Codex #446 P1-2: encrypted AP without a key is refused, not rendered
        let err = build_profile(&profile_args(ProfileChoice::GuestWifi))
            .expect_err("must refuse psk2 without key");
        assert!(err.contains("--ap-key"), "got: {err}");

        let tm = build_profile(&profile_args(ProfileChoice::Travelmate)).expect("travelmate");
        let Profile::Travelmate(tm) = &tm else {
            panic!("travelmate profile");
        };
        assert_eq!(
            (tm.radio.as_str(), tm.timeout, tm.retry, tm.captive),
            ("radio0", 60, 5, true)
        );

        let oc = build_profile(&profile_args(ProfileChoice::OpenClash)).expect("openclash");
        let Profile::OpenClash(oc) = &oc else {
            panic!("openclash profile");
        };
        assert_eq!(
            (
                oc.proxy_type.as_str(),
                oc.core_type.as_str(),
                oc.dns_mode.as_str()
            ),
            ("ss", "Meta", "redir-host")
        );

        let ssl = build_profile(&profile_args(ProfileChoice::Ssl)).expect("ssl");
        let Profile::Ssl(ssl) = &ssl else {
            panic!("ssl profile");
        };
        assert_eq!(ssl.provider, "lancert");
        assert!(ssl.enable_uhttpd_https);
        assert!(ssl.open_port_443_nds);
    }

    #[test]
    fn guest_wifi_choice_gates_surface_at_plan_time() {
        let mut args = profile_args(ProfileChoice::GuestWifi);
        args.ap_key = Some("guestpass".into());
        let gw = build_profile(&args).expect("built");
        let model = model_with(None, "glinet,gl-ar150");
        match plan_profile(&conwrt_core::state::DeviceState::OpenWrt, &model, &gw) {
            Err(conwrt_core::plan::Unsupported::MissingCapability { capability, .. })
                if capability == "wifi" => {}
            other => panic!("expected wifi capability refusal, got {other:?}"),
        }
    }

    #[test]
    fn wireguard_client_required_gates_surface_at_plan_time() {
        let wg = build_profile(&profile_args(ProfileChoice::WireguardClient)).expect("built");
        let model = model_with(None, "glinet,gl-ar150");
        match plan_profile(&conwrt_core::state::DeviceState::OpenWrt, &model, &wg) {
            Err(conwrt_core::plan::Unsupported::InvalidParams(why)) => {
                assert!(why.contains("peer_public_key"), "got: {why}");
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    fn model_with(board_name: Option<&str>, device: &str) -> conwrt_types::DeviceModel {
        conwrt_types::DeviceModel {
            id: "test-model".into(),
            vendor: "Test".into(),
            description: "d".into(),
            openwrt: conwrt_types::OpenwrtInfo {
                target: "x/y".into(),
                device: device.into(),
                profile: "x_y".into(),
                version: "24".into(),
                board_name: board_name.map(str::to_string),
                board_names: None,
                default_ip: None,
                extras: Default::default(),
            },
            capabilities: None,
            flash_methods: None,
            mac_oui: Vec::new(),
            serial_console: None,
            warnings: None,
            extras: Default::default(),
        }
    }

    #[test]
    fn board_name_matches_the_modeled_board_name() {
        // zyxel-gs1920-24 shape: board_name AAOB, device zyxel,gs1920-24hp-v1
        let model = model_with(Some("AAOB"), "zyxel,gs1920-24hp-v1");
        assert!(
            board_matches(&model, "AAOB"),
            "the reported board_name must match"
        );
        assert!(
            board_matches(&model, "zyxel,gs1920-24hp-v1"),
            "DTS alias accepted"
        );
        assert!(!board_matches(&model, "zyxel,gs1900-8hp-a1"));
    }

    #[test]
    fn board_name_falls_back_to_device_for_older_models() {
        let model = model_with(None, "glinet,gl-ar150");
        assert!(board_matches(&model, "glinet,gl-ar150"));
        assert!(!board_matches(&model, "glinet,gl-ar300m"));
    }

    #[test]
    fn board_names_list_matches_fixture_variants() {
        // virtual-x86-64 shape: the QEMU fixture reports a long
        // qemu-derived board_name that only the list knows
        let mut model = model_with(Some("generic"), "generic");
        model.openwrt.board_names = Some(vec![
            "generic".into(),
            "conwrt-conwrt-test-vm".into(),
            "qemu-ubuntu-24-04-pc-v2-i440fx-piix-arch_caps-fix-1996".into(),
        ]);
        assert!(board_matches(&model, "generic"));
        assert!(board_matches(&model, "conwrt-conwrt-test-vm"));
        assert!(board_matches(
            &model,
            "qemu-ubuntu-24-04-pc-v2-i440fx-piix-arch_caps-fix-1996"
        ));
        assert!(!board_matches(&model, "some-other-board"));
    }

    #[test]
    fn blank_board_name_falls_back_to_device() {
        let model = model_with(Some("  "), "glinet,gl-ar150");
        assert!(board_matches(&model, "glinet,gl-ar150"));
    }
}
