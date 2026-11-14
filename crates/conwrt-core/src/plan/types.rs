//! `types` — split out of the former plan.rs monolith (pure move).
use super::*;
use crate::state::DeviceState;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use conwrt_types::DeviceModel;
use core::fmt;
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
    /// Per-AP Nostr identity (npub as `nas_identifier`).
    ApNostrId(ApNostrIdProfile),
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
    /// openperf WiFi performance test client (STA side).
    OpenPerfClient(OpenPerfClientProfile),
    /// openperf WiFi performance test server (JSON-RPC).
    OpenPerfServer(OpenPerfServerProfile),
    /// net4sats admin UI + captive portal (host-side deploy).
    ConfigurationWizzard(ConfigurationWizzardProfile),
    /// FIPS mesh over Bluetooth RFCOMM (experimental).
    FipsBluetoothRfcomm(FipsBluetoothRfcommProfile),
    /// OpenTollGate payment gateway (flash-time portal + payment
    /// config; the ipk deploy is a host-side post-flash step).
    Tollgate(TollgateProfile),
    /// RFC 1918 isolation for TollGate public WiFi.
    TollgateSecurity(TollgateSecurityProfile),
    /// Fleet identity from MAC (canonical derivations, see crate::identity).
    FleetIdentity(FleetIdentityProfile),
    /// TollGate cellular upstream (NR7101-class 5G modem as paid uplink).
    TollgateCellular(TollgateCellularProfile),
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
            Profile::ApNostrId(_) => "ap-nostr-id",
            Profile::VpnOpenvpn(_) => "vpn-openvpn",
            Profile::VpnSurfshark(_) => "vpn-surfshark",
            Profile::VpnIvpn(_) => "vpn-ivpn",
            Profile::VpnMullvad(_) => "vpn-mullvad",
            Profile::VpnNode(_) => "vpn-node",
            Profile::VpnNordvpnIke2(_) => "vpn-nordvpn-ikev2",
            Profile::OpenPerfClient(_) => "openperf_client",
            Profile::OpenPerfServer(_) => "openperf_server",
            Profile::ConfigurationWizzard(_) => "configurationwizzard",
            Profile::FipsBluetoothRfcomm(_) => "fips-bluetooth-rfcomm",
            Profile::Tollgate(_) => "tollgate",
            Profile::TollgateSecurity(_) => "tollgate-security",
            Profile::FleetIdentity(_) => "fleet-identity",
            Profile::TollgateCellular(_) => "tollgate-cellular",
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
            Profile::ApNostrId(_) => &[],
            Profile::VpnOpenvpn(_) => &[],
            Profile::VpnSurfshark(_) => &[],
            Profile::VpnIvpn(_) => &[],
            Profile::VpnMullvad(_) => &[],
            Profile::VpnNode(_) => &[],
            Profile::VpnNordvpnIke2(_) => &[],
            Profile::OpenPerfClient(_) => &["wifi"],
            Profile::OpenPerfServer(_) => &["wifi"],
            Profile::ConfigurationWizzard(_) => &[],
            Profile::FipsBluetoothRfcomm(_) => &["bluetooth"],
            Profile::Tollgate(_) => &[],
            Profile::TollgateSecurity(_) => &["wifi"],
            Profile::FleetIdentity(_) => &["wifi"],
            Profile::TollgateCellular(_) => &["usb"],
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
pub(super) fn parse_openwrt_version(v: &str) -> Option<(u32, Option<u32>)> {
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
    /// Re-read config without the full teardown of a restart (1.x
    /// `network reload`, used by tollgate-cellular).
    Reload,
}

impl fmt::Display for ServiceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceAction::Enable => write!(f, "enable"),
            ServiceAction::Restart => write!(f, "restart"),
            ServiceAction::Start => write!(f, "start"),
            ServiceAction::Reload => write!(f, "reload"),
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
pub(super) fn capabilities_satisfied(
    model: &DeviceModel,
    required: &[&str],
) -> Result<(), Unsupported> {
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
