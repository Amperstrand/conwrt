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
use conwrt_core::plan::{DohProfile, SqmProfile};
use conwrt_core::ssh::TrustMode;
use conwrt_core::{DeviceState, Profile, confirm, diagnose, plan_profile, render_shell};
use conwrt_local_std::fingerprint::fingerprint;
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
#[derive(Subcommand)]
enum Command {
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
    /// Apply a desired-state profile to a device over SSH. DRY-RUN by
    /// default: prints the exact script. Mutating execution requires
    /// --execute AND a fingerprint-confirmed OpenWrt identity.
    Apply {
        /// Desired-state profile to apply.
        #[arg(long)]
        profile: ProfileChoice,
        /// Explicitly forget the stored host key before connecting
        /// (reflash/reimage escape hatch; logged, never silent).
        #[arg(long)]
        relearn_host_key: bool,
        /// Model to plan for (id from `conwrt models`).
        #[arg(long)]
        model_id: String,
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
        /// DoH local listen port (doh).
        #[arg(long)]
        listen_port: Option<u16>,
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
        /// Desired-state profile to plan.
        #[arg(long)]
        profile: ProfileChoice,
        /// Model to plan for (id from `conwrt models`).
        #[arg(long)]
        model_id: String,
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
        /// DoH local listen port (doh).
        #[arg(long)]
        listen_port: Option<u16>,
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
        /// Optional cloud-init network-config file.
        #[arg(long)]
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
        Command::Models { dir } => cmd_models_validate(&dir),
        Command::Agent { command } => cmd_agent(command),
        Command::Maas { command } => cmd_maas(command),
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
            dir,
        } => cmd_diagnose(ip, interface, http_port, ssh_port, &dir),
        Command::Probe { ip, scenario, dir } => cmd_probe(ip, scenario, &dir),
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
            profile,
            model_id,
            download_kbps,
            upload_kbps,
            interface,
            provider,
            listen_port,
            ip,
            port,
            user,
            key,
            password,
            execute,
            dir,
        } => cmd_apply(
            relearn_host_key,
            profile,
            &model_id,
            download_kbps,
            upload_kbps,
            &interface,
            provider,
            listen_port,
            ip,
            port,
            &user,
            key.as_deref(),
            password.as_deref(),
            execute,
            &dir,
        ),
        Command::Plan {
            profile,
            model_id,
            download_kbps,
            upload_kbps,
            interface,
            provider,
            listen_port,
            ip,
            scenario,
            dir,
        } => cmd_plan(
            profile,
            &model_id,
            download_kbps,
            upload_kbps,
            &interface,
            provider,
            listen_port,
            ip,
            scenario,
            &dir,
        ),
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
    for model in registry.models() {
        println!(
            "ok   {} ({}) — {} flash method(s)",
            model.id,
            model.vendor,
            model.flash_methods.as_ref().map_or(0, |m| m.len())
        );
    }
    println!(
        "\n{} model(s) valid in {}",
        registry.models().len(),
        dir.display()
    );
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
    let diagnosis = match runtime.block_on(diagnose(&mut prober, ip, registry.models())) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("diagnose failed: {e}");
            return ExitCode::from(2);
        }
    };
    print_diagnosis(&diagnosis);
    println!("\n(provider: local-std; read-only probes — ping, HTTP GET, SSH banner, ARP)");
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
#[allow(clippy::too_many_arguments)]
fn cmd_plan(
    profile: ProfileChoice,
    model_id: &str,
    download_kbps: Option<u32>,
    upload_kbps: Option<u32>,
    interface: &str,
    provider: Option<String>,
    listen_port: Option<u16>,
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
    let profile = match build_profile(
        profile,
        download_kbps,
        upload_kbps,
        interface,
        provider,
        listen_port,
    ) {
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
    let mut store = FileTrustStore::new(FileTrustStore::default_path());
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
#[allow(clippy::too_many_arguments)]
fn cmd_apply(
    relearn_host_key: bool,
    profile: ProfileChoice,
    model_id: &str,
    download_kbps: Option<u32>,
    upload_kbps: Option<u32>,
    interface: &str,
    provider: Option<String>,
    listen_port: Option<u16>,
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
    let profile = match build_profile(
        profile,
        download_kbps,
        upload_kbps,
        interface,
        provider,
        listen_port,
    ) {
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
    let mut store = FileTrustStore::new(FileTrustStore::default_path());
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
        if !board.is_empty() && *board != model.openwrt.device {
            eprintln!(
                "refused: board_name {board:?} does not match model {} target device {:?}",
                model.id, model.openwrt.device
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
    println!("{}", render_shell(&plan));

    if !execute {
        println!("# dry-run: no changes made. Re-run with --execute to apply.");
        return ExitCode::SUCCESS;
    }
    eprintln!("# executing on {ip} ...");
    match runtime.block_on(conwrt_local_std::execute::apply_plan(&session, &plan)) {
        Ok(outcome) if outcome.fully_verified() => {
            println!("applied:   script exit 0");
            for check in &outcome.verification {
                println!("verified:  ✓ {} (`{}`)", check.description, check.stdout);
            }
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
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
fn build_profile(
    profile: ProfileChoice,
    download_kbps: Option<u32>,
    upload_kbps: Option<u32>,
    interface: &str,
    provider: Option<String>,
    listen_port: Option<u16>,
) -> Result<Profile, String> {
    match profile {
        ProfileChoice::Sqm => match (download_kbps, upload_kbps) {
            (Some(download_kbps), Some(upload_kbps)) => Ok(Profile::Sqm(SqmProfile {
                download_kbps,
                upload_kbps,
                interface: interface.into(),
                ..default_sqm()
            })),
            _ => Err("--download-kbps and --upload-kbps are required for sqm".into()),
        },
        ProfileChoice::Doh => Ok(Profile::Doh(DohProfile {
            provider: provider.unwrap_or_else(|| "cloudflare".into()),
            listen_port: listen_port.unwrap_or(5053),
        })),
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
        let network_config = network_config.map(|p| {
            std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("cannot read network-config {}: {e}", p.display()))
        });
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
            println!("sha256:    {digest} (verified before write)");
            println!("target:    {}", target.display());
            println!(
                "written:   {} bytes (read-back verified)",
                report.bytes_written
            );
            if report.seed_injected {
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
        } => {
            let result = rt.block_on(async {
                let mut client = AgentClient::connect(&addr).await?;
                client.handshake("conwrt-cli").await?;
                client
                    .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
                        resource,
                        exclusive: !shared,
                        on_disconnect: DisconnectPolicy::Abort,
                    })
                    .await
            });
            match result {
                Ok(conwrt_agent_proto::protocol::LeaseResponse::Granted { heartbeat_ms }) => {
                    println!("granted (heartbeat every {heartbeat_ms}ms)");
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
                    println!(
                        "transfer {transfer_id}: {}/{} bytes{}",
                        ack.contiguous,
                        if ack.done { "done" } else { "in progress" },
                        if ack.done { " (done)" } else { "" }
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
