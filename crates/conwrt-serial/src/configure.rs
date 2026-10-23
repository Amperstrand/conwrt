//! # First-contact configuration over serial (Rust port of
//! `scripts/serial-configure.py`)
//!
//! Orchestration over the console driver: show firmware/network/dropbear
//! state, set the LAN IP, toggle password auth, install an SSH key, run an
//! arbitrary command. Command delivery goes through the crate's linted
//! path — all commands are generated as literals on the host (the lint
//! refuses runtime variables by design).
//!
//! Delta over the Python (documented): steps are a declarative plan that
//! is printed before execution, and every write step carries a verify
//! command whose output is returned to the caller.

use crate::console::SerialConsole;
use crate::collect::CmdOutcome;
use std::time::Duration;

/// Per-step collection window (the Python used fixed sleeps; the driver
/// collects until the prompt).
const STEP_WINDOW: Duration = Duration::from_secs(20);

/// One planned console step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Human description (printed before execution).
    pub what: &'static str,
    /// The command to run.
    pub cmd: String,
    /// Optional verification command whose output is reported.
    pub verify: Option<String>,
}

/// Build the show-state plan (firmware + network + dropbear).
pub fn show_plan() -> Vec<Step> {
    vec![
        Step { what: "firmware", cmd: "cat /etc/openwrt_release".into(), verify: None },
        Step { what: "network", cmd: "uci show network.lan".into(), verify: None },
        Step { what: "dropbear", cmd: "uci show dropbear".into(), verify: None },
    ]
}

/// Build the set-LAN-IP plan (write + commit + apply + verify).
pub fn set_ip_plan(ip: &str) -> Vec<Step> {
    vec![
        Step { what: "set lan ipaddr", cmd: format!("uci set network.lan.ipaddr='{ip}'"), verify: None },
        Step { what: "commit", cmd: "uci commit network".into(), verify: None },
        Step { what: "apply", cmd: "ifup lan".into(), verify: None },
        Step { what: "verify", cmd: "uci get network.lan.ipaddr".into(), verify: None },
    ]
}

/// Build the password-auth toggle plan.
pub fn password_auth_plan(enable: bool) -> Vec<Step> {
    let val = if enable { "on" } else { "off" };
    vec![
        Step { what: "set PasswordAuth", cmd: format!("uci set dropbear.@dropbear[0].PasswordAuth='{val}'"), verify: None },
        Step { what: "commit", cmd: "uci commit dropbear".into(), verify: None },
        Step { what: "restart", cmd: "/etc/init.d/dropbear restart".into(), verify: None },
    ]
}

/// Build the authorized-key install plan. The key is embedded as a literal
/// (single-quoted; the lint rejects anything else).
pub fn install_key_plan(key: &str) -> Vec<Step> {
    let key = key.trim();
    vec![
        Step { what: "mkdir", cmd: "mkdir -p /etc/dropbear".into(), verify: None },
        Step { what: "write key", cmd: format!("echo '{key}' > /etc/dropbear/authorized_keys"), verify: None },
        Step { what: "perm", cmd: "chmod 600 /etc/dropbear/authorized_keys".into(), verify: None },
        Step { what: "verify", cmd: "wc -c /etc/dropbear/authorized_keys".into(), verify: None },
    ]
}

/// Result of one executed step.
#[derive(Debug)]
pub struct StepResult {
    /// The step description that ran.
    pub what: &'static str,
    /// 0 = success marker, 1 = failure marker, 2 = timeout.
    pub rc: u8,
    /// Collected console output.
    pub output: String,
}

/// Execute a plan step by step, printing progress; returns each result.
pub fn run_plan(console: &mut SerialConsole, plan: &[Step]) ->
    Result<Vec<StepResult>, crate::io::ConsoleError> {
    let mut out = Vec::new();
    for step in plan {
        let CmdOutcome { rc, output } = console.run(&step.cmd, STEP_WINDOW)?;
        out.push(StepResult { what: step.what, rc, output: output.clone() });
        if let Some(v) = &step.verify {
            let CmdOutcome { rc, output } = console.run(v, STEP_WINDOW)?;
            out.push(StepResult { what: "verify", rc, output });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_plan_is_literal_and_ordered() {
        let plan = set_ip_plan("192.168.12.9");
        assert_eq!(plan[0].cmd, "uci set network.lan.ipaddr='192.168.12.9'");
        assert_eq!(plan[3].cmd, "uci get network.lan.ipaddr");
    }

    #[test]
    fn key_plan_trims_and_quotes() {
        let plan = install_key_plan("  ssh-ed25519 AAAA key@host\n");
        assert_eq!(
            plan[1].cmd,
            "echo 'ssh-ed25519 AAAA key@host' > /etc/dropbear/authorized_keys"
        );
    }

    #[test]
    fn password_toggle_values() {
        assert!(password_auth_plan(true)[0].cmd.contains("'on'"));
        assert!(password_auth_plan(false)[0].cmd.contains("'off'"));
    }

    #[test]
    fn show_plan_is_read_only() {
        for s in show_plan() {
            assert!(s.cmd.starts_with("cat ") || s.cmd.starts_with("uci show"),
                "read-only: {}", s.cmd);
        }
    }
}
