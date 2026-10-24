//! Plan execution over the SSH provider: render → apply → verify.
//!
//! Safety shape (AGENTS.md): the whole plan renders as **one** script and
//! runs in a single exec; verification is a separate, read-only pass whose
//! results are reported per check. Callers are expected to have confirmed
//! the device's OpenWrt identity (fingerprint) before applying — the CLI
//! layer enforces that gate.

use conwrt_core::plan::{Plan, VerificationCheck, render_shell};

use crate::ssh::{SshError, SshSession};

/// Result of one verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// What was checked (from the plan).
    pub description: String,
    /// Whether the output contained the expected marker (and exited 0).
    pub passed: bool,
    /// The command's stdout, for the operator transcript.
    pub stdout: String,
}

/// Outcome of applying a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The exact script that was (or would be) executed.
    pub script: String,
    /// Whether the apply script ran to success (exit 0).
    pub applied: bool,
    /// The apply script's stderr transcript (failure diagnostics).
    pub stderr: String,
    /// Per-check verification results (empty when apply failed).
    pub verification: Vec<VerifyResult>,
}

impl ApplyOutcome {
    /// Apply + every verification check passed.
    #[must_use]
    pub fn fully_verified(&self) -> bool {
        self.applied && self.verification.iter().all(|v| v.passed)
    }
}

/// The exact script `apply_plan` runs: the rendered plan with the
/// executor-level uci-revert preamble spliced in after `set -e`. Every
/// config the plan commits gets `uci -q revert` BEFORE the first
/// mutation, so staging debris an aborted earlier session left in
/// `/tmp/.uci` can never merge into this run's commits (AGENTS.md
/// revert rule — #427). Plan-level `RevertUci` ops stay as-is; a
/// double revert is a harmless no-op.
#[must_use]
pub fn render_apply_script(plan: &Plan) -> String {
    use conwrt_core::plan::PlanOp;
    let mut script = render_shell(plan);
    let mut configs: Vec<String> = Vec::new();
    let push = |configs: &mut Vec<String>, config: String| {
        if !configs.contains(&config) {
            configs.push(config);
        }
    };
    for op in &plan.ops {
        match op {
            PlanOp::CommitUci { config } => push(&mut configs, config.clone()),
            // tether-style plans embed their commits inside verbatim
            // shell payloads — scan those too (Codex #446 P1-1)
            PlanOp::Shell { command } => {
                let mut rest = command.as_str();
                while let Some(at) = rest.find("uci commit ") {
                    rest = &rest[at + "uci commit ".len()..];
                    let token: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !token.is_empty() {
                        push(&mut configs, token);
                    }
                }
            }
            _ => {}
        }
    }
    if configs.is_empty() {
        return script;
    }
    let mut preamble =
        String::from("# revert staged uci baselines before mutating (executor, #427)\n");
    for config in &configs {
        preamble.push_str(&format!("uci -q revert {config} 2>/dev/null || true\n"));
    }
    if let Some(at) = script.find("set -e\n").map(|i| i + "set -e\n".len()) {
        script.insert_str(at, &preamble);
    }
    script
}

/// Apply a plan: run the rendered script, then the read-only verification
/// checks. The script aborts on first failure (`set -e`), which surfaces as
/// `applied == false` with the script's stderr already streamed to the
/// session transcript.
///
/// # Errors
/// Transport-level SSH failures (`SshError`). A failing script or a failing
/// verification check is **data**, not an error — inspect the outcome.
pub async fn apply_plan(session: &SshSession, plan: &Plan) -> Result<ApplyOutcome, SshError> {
    let script = render_apply_script(plan);
    // stdin transport, not exec-command: Dropbear caps the command
    // length and large plans (pia: 9.2KB) die channel-level — see
    // SshSession::exec_stdin. `sh -s` reads the script from stdin;
    // the script's own `set -e` keeps fail-fast semantics identical.
    let output = session.exec_stdin("sh -s", &script).await?;
    let applied = output.exit_code.unwrap_or(1) == 0;

    let mut verification = Vec::new();
    if applied {
        for check in &plan.verification {
            verification.push(run_check(session, check).await?);
        }
    }

    Ok(ApplyOutcome {
        script,
        applied,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        verification,
    })
}

async fn run_check(
    session: &SshSession,
    check: &VerificationCheck,
) -> Result<VerifyResult, SshError> {
    let output = session.exec(&check.command).await?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let passed =
        output.exit_code.unwrap_or(1) == 0 && stdout.contains(check.expect_contains.as_str());
    Ok(VerifyResult {
        description: check.description.clone(),
        passed,
        stdout,
    })
}
