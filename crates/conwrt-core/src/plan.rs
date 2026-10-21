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

/// A desired-state profile: the outcome wanted, never the steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Eliminate bufferbloat with SQM.
    Sqm(SqmProfile),
    /// Encrypted DNS resolution for the whole LAN.
    Doh(DohProfile),
}

impl Profile {
    /// Stable profile identifier (matches 1.x use-case names).
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Profile::Sqm(_) => "sqm",
            Profile::Doh(_) => "doh",
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
                    shell_quote(section),
                    shell_quote(section_type)
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
                    shell_quote(name),
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
        assert!(script.contains("/etc/init.d/'sqm' enable"));
        assert!(script.contains("/etc/init.d/'sqm' restart"));
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
}
