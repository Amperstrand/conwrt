//! Protocol message types shared by controller and agent (issue #108).
//!
//! Everything here is `no_std`-compatible (serde + alloc) so the MCU
//! device-side reuses it verbatim (ADR-0002 tiering).

use alloc::string::String;
use alloc::vec::Vec;
use conwrt_probe_core::milestones::BootMilestone;
use serde::{Deserialize, Serialize};

/// Wire protocol version. Bump on breaking message changes; agents refuse
/// mismatches at the handshake (ADR-0004 §2 — never interpret a mismatch).
pub const PROTOCOL_VERSION: u16 = 1;

/// A capability an agent can expose to a controller (ADR-0003 traits, named
/// on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInfo {
    /// Capability name, e.g. `"serial"`, `"link-probe"`, `"tftp-server"`.
    pub name: String,
    /// Opaque capability-specific detail (counts of UARTs, port ranges…).
    pub detail: Vec<(String, String)>,
}

/// Controller → agent: open a session, negotiate versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// The controller's protocol version (must equal [`PROTOCOL_VERSION`]).
    pub protocol_version: u16,
    /// Free-form controller identification for logs.
    pub controller_id: String,
}

/// Agent → controller: versions match (or refuse with [`HandshakeError`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeOk {
    /// The agent's protocol version.
    pub protocol_version: u16,
    /// The agent's build/version string.
    pub agent_version: String,
    /// Capabilities this agent exposes.
    pub capabilities: Vec<CapabilityInfo>,
}

/// Handshake refusal — always structured, never a dropped connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeError {
    /// Version mismatch: the agent's version vs the requested one.
    VersionMismatch {
        /// What the agent speaks.
        agent: u16,
        /// What the controller asked for.
        requested: u16,
    },
}

/// What happens to an in-flight operation when its controller disconnects
/// (ADR-0004 §5): `Abort` is the default for probes; `Complete` lets a
/// validated flashing finish and park its results for reconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectPolicy {
    /// Cancel on controller loss (default for read-only operations).
    Abort,
    /// Run to completion; results await the controller's return.
    Complete,
}

/// Controller → agent: acquire a resource lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    /// The resource (e.g. `"uart0"`, `"eth0"`, `"power/bay3"`).
    pub resource: String,
    /// Exclusive (default) or shared.
    pub exclusive: bool,
    /// Controller-loss behavior for work holding this lease.
    pub on_disconnect: DisconnectPolicy,
}

/// Agent → controller: lease outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseResponse {
    /// Granted; the heartbeat interval in milliseconds.
    Granted {
        /// How often the controller must send [`Heartbeat`].
        heartbeat_ms: u32,
    },
    /// Refused — held by another controller (who, if known).
    Denied {
        /// Current holder's controller id, when known.
        holder: Option<String>,
    },
}

/// Controller → agent: lease liveness ping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Lease this heartbeat belongs to.
    pub lease_id: u64,
}

/// Agent → controller: a lease expired (controller went silent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseExpired {
    /// The lease that expired.
    pub lease_id: u64,
    /// Why: heartbeat timeout or explicit release.
    pub reason: LeaseExpiryReason,
}

/// Why a lease ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseExpiryReason {
    /// Heartbeats stopped arriving.
    HeartbeatTimeout,
    /// The controller released it.
    Released,
}

/// One chunk of a streamed transfer (firmware-class payloads).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Transfer id (controller-chosen).
    pub transfer_id: u64,
    /// Byte offset of `data` in the whole transfer.
    pub offset: u64,
    /// Total transfer size when known (first chunk carries it).
    pub total: Option<u64>,
    /// The payload bytes.
    pub data: Vec<u8>,
}

/// Agent acknowledgement of contiguous receipt — the resume token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamAck {
    /// Transfer id.
    pub transfer_id: u64,
    /// Contiguous bytes received so far (resume from exactly here).
    pub contiguous: u64,
    /// Whether the transfer is complete and verified-sized.
    pub done: bool,
}

// ---- #215 slice 5: standalone detect surface ----

/// Controller → agent: arm boot-milestone detection on a UART port
/// (`DetectStart`). Re-arming restarts the milestone tracker — each
/// detection session latches every milestone at most once (the
/// `serial_monitor.py` per-monitor-lifetime semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectRequest {
    /// Port index (0-based, as advertised in capabilities).
    pub port: u8,
}

/// Controller → agent: query the latched detection findings
/// (`DetectStatus`) — the reconnecting controller's catch-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectStatusQuery {
    /// Port index the detection session runs on.
    pub port: u8,
}

/// One latched detection finding (agent → controller, unsolicited
/// [`crate::dispatch::AgentEvent::DetectFinding`] and inside
/// [`DetectReport`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectFinding {
    /// Port the detection session runs on.
    pub port: u8,
    /// The milestone that latched.
    pub milestone: BootMilestone,
    /// The console line that carried it (stripped, capped).
    pub detail: String,
}

/// The current state of a port's detection session (the
/// `DetectStart`/`DetectStatus` reply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectReport {
    /// Port the detection session runs on.
    pub port: u8,
    /// Every finding latched this session, in latch order.
    pub findings: Vec<DetectFinding>,
}
