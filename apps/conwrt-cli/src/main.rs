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

use clap::{Parser, Subcommand, ValueEnum};
use conwrt_core::mock::{MockProber, NamedScenario};
use conwrt_core::{DeviceState, diagnose};
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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScenarioChoice {
    Off,
    Unreachable,
    Uboot,
    Openwrt,
    Stock,
}

impl ScenarioChoice {
    fn named(self) -> NamedScenario {
        match self {
            ScenarioChoice::Off => NamedScenario::Off,
            ScenarioChoice::Unreachable => NamedScenario::Unreachable,
            ScenarioChoice::Uboot => NamedScenario::UbootRecovery,
            ScenarioChoice::Openwrt => NamedScenario::OpenWrt,
            ScenarioChoice::Stock => NamedScenario::StockVendor,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Models { dir } => cmd_models_validate(&dir),
        Command::Identify { mac, dir } => cmd_identify(&mac, &dir),
        Command::Probe { ip, scenario, dir } => cmd_probe(ip, scenario, &dir),
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
    let (registry, dir_display) = load_registry(dir);
    let mut prober = MockProber::responding(ip, scenario.named());
    let diagnosis = match pollster::block_on(diagnose(&mut prober, ip, registry.models())) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("probe failed: {e}");
            return ExitCode::from(2);
        }
    };
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
    println!(
        "\n(provider: scripted mock; models from {} — local-std and remote \
         providers arrive with M2/M3)",
        dir_display.display()
    );
    ExitCode::SUCCESS
}
