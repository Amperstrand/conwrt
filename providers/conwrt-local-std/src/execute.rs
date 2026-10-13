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

/// Apply a plan: run the rendered script, then the read-only verification
/// checks. The script aborts on first failure (`set -e`), which surfaces as
/// `applied == false` with the script's stderr already streamed to the
/// session transcript.
///
/// # Errors
/// Transport-level SSH failures (`SshError`). A failing script or a failing
/// verification check is **data**, not an error — inspect the outcome.
pub async fn apply_plan(session: &SshSession, plan: &Plan) -> Result<ApplyOutcome, SshError> {
    let script = render_shell(plan);
    let output = session.exec(&script).await?;
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
