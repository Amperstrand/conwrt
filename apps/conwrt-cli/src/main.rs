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

use clap::{Parser, Subcommand, ValueEnum};
use conwrt_core::mock::{MockProber, NamedScenario};
use conwrt_core::plan::SqmProfile;
use conwrt_core::{DeviceState, Profile, diagnose, plan_profile};
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
    /// Plan a desired-state profile for a diagnosed device (read-only; mock
    /// transport — the M7 executor applies plans later).
    Plan {
        /// Desired-state profile to plan.
        #[arg(long)]
        profile: ProfileChoice,
        /// Model to plan for (id from `conwrt models`).
        #[arg(long)]
        model_id: String,
        /// Shaper download rate in Kbit/s (sqm).
        #[arg(long)]
        download_kbps: u32,
        /// Shaper upload rate in Kbit/s (sqm).
        #[arg(long)]
        upload_kbps: u32,
        /// UCI network name to shape (sqm).
        #[arg(long, default_value = "wan")]
        interface: String,
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Models { dir } => cmd_models_validate(&dir),
        Command::Identify { mac, dir } => cmd_identify(&mac, &dir),
        Command::Diagnose {
            ip,
            interface,
            http_port,
            ssh_port,
            dir,
        } => cmd_diagnose(ip, interface, http_port, ssh_port, &dir),
        Command::Probe { ip, scenario, dir } => cmd_probe(ip, scenario, &dir),
        Command::Plan {
            profile,
            model_id,
            download_kbps,
            upload_kbps,
            interface,
            ip,
            scenario,
            dir,
        } => cmd_plan(
            profile,
            &model_id,
            download_kbps,
            upload_kbps,
            &interface,
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
    download_kbps: u32,
    upload_kbps: u32,
    interface: &str,
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
    let profile = match profile {
        ProfileChoice::Sqm => Profile::Sqm(SqmProfile {
            download_kbps,
            upload_kbps,
            interface: interface.into(),
            ..default_sqm()
        }),
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
