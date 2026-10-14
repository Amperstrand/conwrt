//! # conwrt-agent
//!
//! The agent binary: runs on any Linux (OpenWrt, bench hosts, VMs),
//! listens for controller connections, and exports the configured
//! capabilities over the conwrt agent protocol (#108).
//!
//! ```text
//! conwrt-agent --listen 0.0.0.0:8400 --capability serial:uarts=2 --capability link-probe
//! ```

use clap::Parser;
use conwrt_agent_proto::agent::{AgentConfig, run_agent};
use conwrt_agent_proto::protocol::CapabilityInfo;

#[derive(Parser)]
#[command(
    name = "conwrt-agent",
    version,
    about = "Conwrt agent — exports capabilities to controllers"
)]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8400")]
    listen: String,

    /// Capabilities to advertise, as name:key=value:key=value...
    /// e.g. --capability serial:uarts=2 --capability link-probe
    #[arg(long = "capability", value_name = "SPEC")]
    capabilities: Vec<String>,
}

fn parse_capabilities(specs: &[String]) -> Vec<CapabilityInfo> {
    specs
        .iter()
        .map(|spec| {
            let (name, rest) = match spec.split_once(':') {
                Some((n, r)) => (n, r),
                None => (spec.as_str(), ""),
            };
            let detail = rest
                .split(',')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect();
            CapabilityInfo {
                name: name.to_string(),
                detail,
            }
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = AgentConfig {
        listen: cli.listen.clone(),
        capabilities: parse_capabilities(&cli.capabilities),
        ..Default::default()
    };
    eprintln!(
        "conwrt-agent {} listening on {} ({} capabilities)",
        env!("CARGO_PKG_VERSION"),
        config.listen,
        config.capabilities.len()
    );
    if let Err(e) = run_agent(config).await {
        eprintln!("agent error: {e}");
        std::process::exit(1);
    }
}
