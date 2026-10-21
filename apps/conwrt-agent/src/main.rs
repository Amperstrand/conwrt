//! # conwrt-agent
//!
//! The agent binary: runs on any Linux (OpenWrt, bench hosts, VMs),
//! listens for controller connections, and exports the configured
//! capabilities over the conwrt agent protocol (#108).
//!
//! ```text
//! conwrt-agent --capability serial:uarts=2:baud=115200 --capability link-probe
//! ```
//!
//! Listens on loopback only by default. The protocol has no transport
//! authentication yet (ADR-0004 §§4/8); a non-loopback listener is
//! refused unless `--insecure-allow-non-loopback` explicitly accepts
//! the exposure (isolated test guests/VMs only).

use std::net::ToSocketAddrs;

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
    /// Address to listen on (default: loopback).
    ///
    /// Non-loopback listeners are refused without
    /// --insecure-allow-non-loopback: the protocol has no transport
    /// authentication yet (ADR-0004 §§4/8), so anyone who can reach
    /// the port can take leases and push stream data.
    #[arg(long, default_value = "127.0.0.1:8400")]
    listen: String,

    /// Explicitly accept the risk of a non-loopback listener (ADR-0004 §§4/8).
    ///
    /// For isolated test guests/VMs (e.g. a QEMU host-forwarded OpenWrt
    /// image) where every reachable peer is trusted.
    #[arg(long)]
    insecure_allow_non_loopback: bool,

    /// Capabilities to advertise, as name:key=value:key=value...
    /// e.g. --capability serial:uarts=2:baud=115200 --capability link-probe
    #[arg(long = "capability", value_name = "SPEC")]
    capabilities: Vec<String>,
}

/// Refuse non-loopback listeners until the protocol grows transport
/// authentication (pairing + session encryption, ADR-0004 §§4/8).
fn validate_listen(listen: &str, allow_non_loopback: bool) -> Result<(), String> {
    let addrs: Vec<_> = listen
        .to_socket_addrs()
        .map_err(|e| format!("invalid --listen {listen:?}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("--listen {listen:?} resolved to no addresses"));
    }
    if !allow_non_loopback && addrs.iter().any(|a| !a.ip().is_loopback()) {
        return Err(format!(
            "refusing non-loopback --listen {listen:?}: the agent protocol has no transport \
             authentication yet (ADR-0004 §§4/8), so anyone who can reach the port can take \
             leases and push stream data; pass --insecure-allow-non-loopback to accept this \
             risk on an isolated network"
        ));
    }
    Ok(())
}

fn parse_capabilities(specs: &[String]) -> Result<Vec<CapabilityInfo>, String> {
    specs
        .iter()
        .map(|spec| {
            let (name, rest) = match spec.split_once(':') {
                Some((n, r)) => (n, r),
                None => (spec.as_str(), ""),
            };
            if name.is_empty() {
                return Err(format!("capability spec {spec:?} has an empty name"));
            }
            let mut detail = Vec::new();
            if !rest.is_empty() {
                for pair in rest.split(':') {
                    let (k, v) = pair.split_once('=').ok_or_else(|| {
                        format!(
                            "capability detail {pair:?} in {spec:?} is not key=value \
                             (syntax: name:key=value:key=value)"
                        )
                    })?;
                    for part in [k, v] {
                        if part.is_empty() {
                            return Err(format!(
                                "capability detail {pair:?} in {spec:?} has an empty key or value"
                            ));
                        }
                        if part.contains(',') {
                            return Err(format!(
                                "capability detail {pair:?} in {spec:?} contains a comma; \
                                 details are colon-separated (name:key=value:key=value)"
                            ));
                        }
                    }
                    detail.push((k.to_string(), v.to_string()));
                }
            } else if spec.contains(':') {
                return Err(format!(
                    "capability spec {spec:?} ends with a colon but declares no details"
                ));
            }
            Ok(CapabilityInfo {
                name: name.to_string(),
                detail,
            })
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = validate_listen(&cli.listen, cli.insecure_allow_non_loopback) {
        eprintln!("conwrt-agent: {e}");
        std::process::exit(2);
    }
    let capabilities = match parse_capabilities(&cli.capabilities) {
        Ok(caps) => caps,
        Err(e) => {
            eprintln!("conwrt-agent: {e}");
            std::process::exit(2);
        }
    };
    let config = AgentConfig {
        listen: cli.listen.clone(),
        capabilities,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_is_loopback() {
        let cli = Cli::try_parse_from(["conwrt-agent"]).unwrap();
        assert_eq!(cli.listen, "127.0.0.1:8400");
    }

    #[test]
    fn capability_details_use_documented_colon_syntax() {
        let caps = parse_capabilities(&["serial:uarts=2:baud=115200".to_string()]).unwrap();
        assert_eq!(caps[0].name, "serial");
        assert_eq!(
            caps[0].detail,
            vec![
                ("uarts".to_string(), "2".to_string()),
                ("baud".to_string(), "115200".to_string()),
            ]
        );
    }

    #[test]
    fn capability_without_details_is_bare_name() {
        let caps = parse_capabilities(&["link-probe".to_string()]).unwrap();
        assert_eq!(caps[0].name, "link-probe");
        assert!(caps[0].detail.is_empty());
    }

    #[test]
    fn single_detail_keeps_working() {
        let caps = parse_capabilities(&["tftp-server:port=69".to_string()]).unwrap();
        assert_eq!(caps[0].name, "tftp-server");
        assert_eq!(caps[0].detail, vec![("port".to_string(), "69".to_string())]);
    }

    #[test]
    fn malformed_details_are_rejected_not_dropped() {
        for bad in [
            "serial:uarts",               // not key=value
            "serial:uarts=",              // empty value
            "serial:=2",                  // empty key
            "serial:uarts=2,baud=115200", // legacy comma syntax
            ":uarts=2",                   // empty name
            "serial:",                    // colon promises a detail
        ] {
            assert!(
                parse_capabilities(&[bad.to_string()]).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn loopback_listens_are_accepted() {
        for good in ["127.0.0.1:8400", "[::1]:8400", "localhost:8400"] {
            assert!(validate_listen(good, false).is_ok(), "{good} should pass");
        }
    }

    #[test]
    fn non_loopback_listen_is_refused_without_opt_in() {
        for bad in ["0.0.0.0:8400", "192.168.1.10:8400", "[::]:8400"] {
            let err = validate_listen(bad, false).unwrap_err();
            assert!(err.contains("--insecure-allow-non-loopback"), "{err}");
        }
    }

    #[test]
    fn non_loopback_listen_requires_explicit_opt_in() {
        assert!(validate_listen("0.0.0.0:8400", true).is_ok());
    }

    #[test]
    fn unresolvable_listen_is_rejected() {
        assert!(validate_listen("not-an-address", false).is_err());
        assert!(validate_listen("", false).is_err());
    }
}
