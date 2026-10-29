//! Plan execution over the SSH provider: render → apply → verify.
//!
//! Safety shape (AGENTS.md): the whole plan renders as **one** script and
//! runs in a single exec; verification is a separate, read-only pass whose
//! results are reported per check. Callers are expected to have confirmed
//! the device's OpenWrt identity (fingerprint) before applying — the CLI
//! layer enforces that gate.
//!
//! Deadman/recovery window (#555): a plan that restarts networking can
//! sever the SSH channel mid-script (`/etc/init.d/network restart` inside
//! the single `sh -s` exec), leaving the plan half-applied and the
//! executor with no feedback path. For those plans the executor arms a
//! DEVICE-SIDE deadman before the first mutation: uci snapshots of every
//! config the plan commits, plus a detached revert script that restores
//! the snapshots and restarts networking again if the window expires
//! without a cancel. The cancel is sent by the executor once the apply
//! is verified good — and must be CONFIRMED by the device (an
//! unconfirmed cancel is a pending revert, never a success); a
//! channel-losing apply instead enters a bounded
//! reconnect-and-verify loop (`apply_plan_with_recovery`) so the
//! no-feedback period is bounded and the recovery entry is defined.

use std::future::Future;
use std::time::Duration;

use conwrt_core::plan::{Plan, PlanOp, ServiceAction, VerificationCheck, render_shell};

use crate::ssh::{SshError, SshSession};

/// Fixed, self-documenting deadman state directory on the device (one
/// executor per device is the lease model — a fixed path also lets a
/// stale arming from a crashed earlier apply be cleaned by re-arming).
pub const DEADMAN_DIR: &str = "/tmp/conwrt-deadman";

/// Host-side env override for the window length (seconds), baked into the
/// armed script at render time and used as the recovery-loop deadline.
pub const DEADMAN_WINDOW_ENV: &str = "CONWRT_DEADMAN_WINDOW";

const DEFAULT_DEADMAN_WINDOW_SECS: u64 = 300;
const DEFAULT_RECOVERY_POLL_SECS: u64 = 5;
const RECOVERY_POLL_ENV: &str = "CONWRT_DEADMAN_POLL_SECS";

/// Result of one verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// What was being checked (from the plan).
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
    /// Whether the apply script ran to success (exit 0). On the recovered
    /// path (`channel_lost`) this is set only when every verification
    /// check passed on the reconnected device — the evidence the apply
    /// actually landed.
    pub applied: bool,
    /// The apply script's stderr transcript (failure diagnostics). On the
    /// recovered path this carries the channel-loss cause instead.
    pub stderr: String,
    /// Per-check verification results (empty when apply failed).
    pub verification: Vec<VerifyResult>,
    /// Whether the deadman window was armed (network-restarting plan).
    pub deadman_armed: bool,
    /// The apply channel died before an exit status was collected — the
    /// script's fate was unknown at transport level.
    pub channel_lost: bool,
    /// The device-side deadman was cancelled after a verified-good apply.
    pub deadman_cancelled: bool,
}

impl ApplyOutcome {
    /// Apply + every verification check passed. On a deadman-armed plan
    /// this ALSO requires a device-confirmed cancel: readbacks alone do
    /// not make the configuration persist while rollback stays armed —
    /// an unconfirmed cancel means the device reverts at window expiry
    /// (Codex #597 P1), which is not a success.
    #[must_use]
    pub fn fully_verified(&self) -> bool {
        self.applied
            && self.verification.iter().all(|v| v.passed)
            && (!self.deadman_armed || self.deadman_cancelled)
    }
}

/// The deadman window length in seconds (env-overridable for tests and
/// slow networks; invalid values fall back to the default).
#[must_use]
pub fn deadman_window_secs() -> u64 {
    std::env::var(DEADMAN_WINDOW_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_DEADMAN_WINDOW_SECS)
}

/// The recovery-loop poll cadence in seconds (env-tunable so tests can
/// run a short window without sleeping the production cadence).
fn recovery_poll_secs() -> u64 {
    std::env::var(RECOVERY_POLL_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_RECOVERY_POLL_SECS)
}

/// The command the executor sends to cancel an armed deadman. `current`
/// is the symlink the arm block points at ITS generation directory — a
/// cancel can therefore only ever reach the newest arming, never a
/// superseded process still polling its own (baked-in) generation path
/// (Codex #597 P1: generation isolation).
#[must_use]
pub fn deadman_cancel_cmd() -> String {
    format!("touch {DEADMAN_DIR}/current/cancel && echo deadman-cancelled")
}

/// Does this plan restart networking (the channel-severing class)?
///
/// Detection covers the typed op (`Service { network, Restart }`) and the
/// verbatim escape hatch (`/etc/init.d/network restart` inside a `Shell`
/// payload) — the same dual scan shape as the #427 commit collector.
fn plan_restarts_network(plan: &Plan) -> bool {
    plan.ops.iter().any(|op| match op {
        PlanOp::Service { name, action } => name == "network" && *action == ServiceAction::Restart,
        PlanOp::Shell { command } => command.contains("/etc/init.d/network restart"),
        _ => false,
    })
}

/// The device-side deadman arm block: snapshot every config the plan
/// commits, stage a detached revert script, and start its cancel-poll
/// window. Runs under the apply script's `set -e`; every step is either
/// unconditional-success or explicitly guarded.
///
/// Generation isolation (Codex #597 P1): each arming gets its own
/// `$$-$(date +%s)` subdirectory and the revert script derives its state
/// dir from its own path — a stale process from an earlier arming can
/// never observe a newer apply's cancel flag or snapshots. Re-arming
/// first RETIRES any previous process (cancel-neutralize + verified
/// kill) before replacing the state, so one executor per device means
/// one live deadman at a time (the lease model).
fn render_deadman_arm(configs: &[String], window_secs: u64) -> String {
    let poll = recovery_poll_secs();
    let polls = window_secs.div_ceil(poll);
    let mut snapshots = String::new();
    for config in configs {
        snapshots.push_str(&format!(
            "uci -q export {config} > \"$DM_DIR/snapshots/{config}.uci\" 2>/dev/null \
             || rm -f \"$DM_DIR/snapshots/{config}.uci\"\n"
        ));
    }
    format!(
        r#"# --- deadman: this plan restarts networking (executor, #555) ---
# A mid-script /etc/init.d/network restart can sever the SSH channel with
# the plan half-applied and the executor blind. The snapshots below are
# the pre-apply uci state of every config this plan commits; if the
# cancel flag does not appear within {window_secs}s, revert.sh re-imports
# them and restarts networking (the recovery entry). The executor cancels
# via the `current` symlink once the apply is verified good.
DM_ROOT={DEADMAN_DIR}
DM_GEN="$$-$(date +%s)"
DM_DIR="$DM_ROOT/$DM_GEN"
# Retire any previous arming BEFORE replacing its state (supersede): a
# still-polling stale revert.sh must not survive into this apply's
# window — its earlier deadline would roll THIS apply back prematurely.
if [ -d "$DM_ROOT" ]; then
    # neutralize: its next poll sees the cancel flag and exits harmlessly
    touch "$DM_ROOT/current/cancel" 2>/dev/null || true
    __dm_old_pid="$(cat "$DM_ROOT/pid" 2>/dev/null || true)"
    case "$__dm_old_pid" in
        ''|*[!0-9]*) ;;
        *) if grep -q conwrt-deadman "/proc/$__dm_old_pid/cmdline" 2>/dev/null; then
               kill "$__dm_old_pid" 2>/dev/null || true
           fi ;;
    esac
fi
rm -rf "$DM_ROOT"
mkdir -p "$DM_DIR/snapshots"
{snapshots}cat > "$DM_DIR/revert.sh" <<'CONWRT_DM_EOF'
#!/bin/sh
# conwrt deadman revert (#555) - runs detached; survives apply-channel death
# Owns exactly the generation directory it lives in (re-arm supersedes).
DM_DIR=$(dirname "$0")
i=0
while [ "$i" -lt {polls} ]; do
    [ -e "$DM_DIR/cancel" ] && exit 0
    sleep {poll}
    i=$((i+1))
done
# A cancel landing during the FINAL sleep is still inside the advertised
# window — recheck before reverting, or a verified+cancelled apply gets
# rolled back anyway (Codex #597 P1).
[ -e "$DM_DIR/cancel" ] && exit 0
logger -t conwrt-deadman "apply window expired without cancel - reverting"
touch "$DM_DIR/fired"
for __dm_f in "$DM_DIR/snapshots"/*.uci; do
    [ -s "$__dm_f" ] || continue
    __dm_c="$(basename "$__dm_f" .uci)"
    uci -q import "$__dm_c" < "$__dm_f" && uci -q commit "$__dm_c"
done
/etc/init.d/network restart >/dev/null 2>&1
[ -s "$DM_DIR/snapshots/firewall.uci" ] && /etc/init.d/firewall restart >/dev/null 2>&1 || true
logger -t conwrt-deadman "revert applied (pre-apply uci restored)"
CONWRT_DM_EOF
chmod +x "$DM_DIR/revert.sh"
ln -sfn "$DM_DIR" "$DM_ROOT/current"
setsid "$DM_DIR/revert.sh" >/dev/null 2>&1 < /dev/null &
echo $! > "$DM_ROOT/pid"
"#,
        snapshots = snapshots,
        polls = polls,
    )
}

/// The exact script `apply_plan` runs: the rendered plan with the
/// executor-level uci-revert preamble spliced in after `set -e`, plus —
/// for network-restarting plans — the deadman arm block. Every config the
/// plan commits gets `uci -q revert` BEFORE the first mutation, so
/// staging debris an aborted earlier session left in `/tmp/.uci` can
/// never merge into this run's commits (AGENTS.md revert rule — #427).
/// Plan-level `RevertUci` ops stay as-is; a double revert is a harmless
/// no-op.
#[must_use]
pub fn render_apply_script(plan: &Plan) -> String {
    render_apply_script_windowed(plan, deadman_window_secs())
}

/// [`render_apply_script`] with an explicit deadman window: callers that
/// bound the recovery loop (e.g. [`apply_plan_with_recovery_windowed`])
/// MUST arm the device-side deadman with the SAME window — a host-side
/// recovery deadline that expires before the device reverts leaves the
/// executor reporting "window expired, reverting" while the device is
/// still waiting (and a device that reverts before the host gives up
/// races the cancel). One window, both sides.
#[must_use]
pub fn render_apply_script_windowed(plan: &Plan, window_secs: u64) -> String {
    let mut script = render_shell(plan);
    let configs = committed_configs(plan);
    if configs.is_empty() {
        return script;
    }
    let mut preamble =
        String::from("# revert staged uci baselines before mutating (executor, #427)\n");
    for config in &configs {
        preamble.push_str(&format!("uci -q revert {config} 2>/dev/null || true\n"));
    }
    if plan_restarts_network(plan) {
        preamble.push_str(&render_deadman_arm(&configs, window_secs));
    }
    if let Some(at) = script.find("set -e\n").map(|i| i + "set -e\n".len()) {
        script.insert_str(at, &preamble);
    }
    script
}

/// Every uci config this plan commits — typed `CommitUci` ops plus
/// tether-style `uci commit <cfg>` embedded in verbatim shell payloads
/// (Codex #446 P1-1).
fn committed_configs(plan: &Plan) -> Vec<String> {
    let mut configs: Vec<String> = Vec::new();
    let push = |configs: &mut Vec<String>, config: String| {
        if !configs.contains(&config) {
            configs.push(config);
        }
    };
    for op in &plan.ops {
        match op {
            PlanOp::CommitUci { config } => push(&mut configs, config.clone()),
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
    configs
}

/// Apply a plan with no recovery path: run the rendered script, then the
/// read-only verification checks. The script aborts on first failure
/// (`set -e`), which surfaces as `applied == false` with the script's
/// stderr already streamed to the session transcript. A channel that
/// dies before an exit status on a network-restarting plan surfaces as
/// `applied == false` with `channel_lost == true` (the deadman stays
/// armed on the device and will revert at window expiry).
///
/// # Errors
/// Transport-level SSH failures (`SshError`). A failing script or a failing
/// verification check is **data**, not an error — inspect the outcome.
pub async fn apply_plan(session: &SshSession, plan: &Plan) -> Result<ApplyOutcome, SshError> {
    let script = render_apply_script(plan);
    let armed = plan_restarts_network(plan);
    let output = session.exec_stdin("sh -s", &script).await?;
    // A channel that closed before delivering an exit status on a
    // network-restarting plan means the script's fate is UNKNOWN — it may
    // still be running device-side. That is the #555 wedge class: report
    // it as fate-unknown (never as a clean failure); the armed deadman
    // bounds the damage at window expiry.
    if armed && output.exit_code.is_none() {
        return Ok(fate_unknown_outcome(
            script,
            "apply channel closed before exit status (network-restart class)",
        ));
    }
    finish_apply(session, plan, script, armed, &output).await
}

/// Apply a plan with a deadman recovery path (#555): like [`apply_plan`],
/// but a channel that dies on a network-restarting plan — transport error
/// or missing exit status — enters a bounded reconnect-and-verify loop
/// (the same window the device-side deadman waits). If the device comes
/// back and every verification check passes, the deadman is cancelled and
/// the outcome reports the recovery; if the window expires, the error
/// names the revert the device is about to perform. `reconnect` should
/// build a FRESH session to the same device (connection parameters may
/// not be reused from a dead channel).
///
/// # Errors
/// Transport-level SSH failures. A failing script or verification check
/// is data (inspect the outcome); a lost channel that never recovers
/// within the window is an `SshError` whose message names the deadman
/// revert.
pub async fn apply_plan_with_recovery<F, Fut>(
    session: &SshSession,
    plan: &Plan,
    reconnect: F,
) -> Result<ApplyOutcome, SshError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SshSession, SshError>>,
{
    apply_plan_inner(
        session,
        plan,
        reconnect,
        deadman_window_secs(),
        recovery_poll_secs(),
    )
    .await
}

/// Explicit-window variant for tests and callers that derive the window
/// from their own policy (same semantics as [`apply_plan_with_recovery`]).
pub async fn apply_plan_with_recovery_windowed<F, Fut>(
    session: &SshSession,
    plan: &Plan,
    reconnect: F,
    window_secs: u64,
    poll_secs: u64,
) -> Result<ApplyOutcome, SshError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SshSession, SshError>>,
{
    apply_plan_inner(session, plan, reconnect, window_secs, poll_secs).await
}

async fn apply_plan_inner<F, Fut>(
    session: &SshSession,
    plan: &Plan,
    mut reconnect: F,
    window_secs: u64,
    poll_secs: u64,
) -> Result<ApplyOutcome, SshError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SshSession, SshError>>,
{
    let script = render_apply_script_windowed(plan, window_secs);
    let armed = plan_restarts_network(plan);
    // stdin transport, not exec-command: Dropbear caps the command
    // length and large plans (pia: 9.2KB) die channel-level — see
    // SshSession::exec_stdin. `sh -s` reads the script from stdin;
    // the script's own `set -e` keeps fail-fast semantics identical.
    let output = match session.exec_stdin("sh -s", &script).await {
        Ok(output) => output,
        Err(e) if armed => {
            return channel_lost_path(plan, script, e, &mut reconnect, window_secs, poll_secs)
                .await;
        }
        Err(e) => return Err(e),
    };
    // A channel that closed before delivering an exit status on a
    // network-restarting plan means the script's fate is UNKNOWN — it may
    // still be running device-side. That is the #555 wedge class.
    if armed && output.exit_code.is_none() {
        let cause = SshError::Transport(
            "apply channel closed before exit status (network-restart class)".into(),
        );
        return channel_lost_path(plan, script, cause, &mut reconnect, window_secs, poll_secs)
            .await;
    }
    finish_apply(session, plan, script, armed, &output).await
}

/// Send the deadman cancel and require the DEVICE to confirm it (exit 0
/// — the `touch` through the `current` symlink succeeded). A transport
/// blip or a failed touch must not doom a verified apply to rollback,
/// so the cancel is retried a bounded number of times on the live
/// channel. Returns false only when the cancel stays unconfirmed —
/// callers must then treat the outcome as NOT successful: the device
/// reverts at window expiry (Codex #597 P1).
async fn confirm_deadman_cancel(session: &SshSession) -> bool {
    const CANCEL_ATTEMPTS: u32 = 3;
    for _ in 0..CANCEL_ATTEMPTS {
        let confirmed = session
            .exec(&deadman_cancel_cmd())
            .await
            .map(|o| o.exit_code.unwrap_or(1) == 0)
            .unwrap_or(false);
        if confirmed {
            return true;
        }
    }
    false
}

/// Shared tail of both apply entry points: run the read-only verification
/// pass, cancel an armed deadman when the apply is verified good.
async fn finish_apply(
    session: &SshSession,
    plan: &Plan,
    script: String,
    armed: bool,
    output: &crate::ssh::ExecOutput,
) -> Result<ApplyOutcome, SshError> {
    let applied = output.exit_code.unwrap_or(1) == 0;
    let mut verification = Vec::new();
    if applied {
        for check in &plan.verification {
            verification.push(run_check(session, check).await?);
        }
    }
    let mut cancelled = false;
    if armed && !verification.is_empty() && verification.iter().all(|v| v.passed) {
        cancelled = confirm_deadman_cancel(session).await;
    }

    Ok(ApplyOutcome {
        script,
        applied,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        verification,
        deadman_armed: armed,
        channel_lost: false,
        deadman_cancelled: cancelled,
    })
}

fn fate_unknown_outcome(script: String, cause: &str) -> ApplyOutcome {
    ApplyOutcome {
        script,
        applied: false,
        stderr: format!("{cause} — deadman armed, reverts at window expiry"),
        verification: Vec::new(),
        deadman_armed: true,
        channel_lost: true,
        deadman_cancelled: false,
    }
}

/// The #555 bounded no-feedback window: poll for the device (reconnect),
/// and once reachable re-run the read-only verification pass. Verified
/// good → cancel the deadman (confirmed — retried through the window if
/// the cancel write fails; an unconfirmed cancel is a pending revert,
/// not a success) and report recovery; window exhausted → an error
/// naming the revert. A plan with no verification checks cannot prove
/// the apply landed, so it never takes the verified-good exit — the
/// deadman reverts (conservative by construction).
async fn channel_lost_path<F, Fut>(
    plan: &Plan,
    script: String,
    cause: SshError,
    reconnect: &mut F,
    window: u64,
    poll_secs: u64,
) -> Result<ApplyOutcome, SshError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SshSession, SshError>>,
{
    let poll = Duration::from_secs(poll_secs);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(window);
    // Immediate first reconnect attempt: a brief interface bounce may be
    // over already; each further attempt waits one poll interval.
    while tokio::time::Instant::now() < deadline {
        let Ok(session) = reconnect().await else {
            tokio::time::sleep(poll).await;
            continue;
        };
        let mut verification = Vec::new();
        let mut transport_ok = true;
        for check in &plan.verification {
            match run_check(&session, check).await {
                Ok(result) => verification.push(result),
                Err(_) => {
                    transport_ok = false;
                    break;
                }
            }
        }
        // Verified-good exit requires a CONFIRMED cancel: if the cancel
        // write fails we fall through and retry the whole
        // reachable→verify→cancel cycle until the deadline — an
        // unconfirmed cancel is a pending revert, not a success
        // (Codex #597 P1).
        if transport_ok
            && !verification.is_empty()
            && verification.iter().all(|v| v.passed)
            && confirm_deadman_cancel(&session).await
        {
            return Ok(ApplyOutcome {
                script,
                applied: true,
                stderr: format!("{cause} — reconnected within the window"),
                verification,
                deadman_armed: true,
                channel_lost: true,
                deadman_cancelled: true,
            });
        }
        // Reachable but not verified-good (or cancel still unconfirmed):
        // a just-restarted network may still be converging — sleep one
        // poll interval and retry until the deadline.
        tokio::time::sleep(poll).await;
    }
    Err(SshError::Transport(format!(
        "{cause}; deadman armed — the device re-imports its pre-apply uci \
         snapshots and restarts networking when the {window}s window expires"
    )))
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
