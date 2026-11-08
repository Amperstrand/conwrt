//! The agent-side server (#108): TCP accept loop, per-connection handler,
//! dispatch to the lease table + stream store.
//!
//! One connection at a time (the postcard-rpc-spike model: a dead
//! connection ends the handler and the accept loop takes the next
//! controller). State (leases, streams) lives in an `Arc<Mutex<>>` so it
//! survives reconnections — the controller-loss/resume semantics of
//! ADR-0004 §5.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};

use crate::dispatch::AgentEvent;
use crate::dispatch::{WireEndpoint, WireError, WireFrame, WireResult, decode_frame, encode_frame};
use crate::leases::{LeaseDenied, LeaseError, LeaseTable};
use crate::protocol::{
    CapabilityInfo, HandshakeError, HandshakeOk, HandshakeRequest, LeaseResponse, PROTOCOL_VERSION,
    StreamAck,
};
use crate::wire::{CobsReceiver, CobsSender};

/// Agent configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Address to listen on (e.g. `"0.0.0.0:8400"`).
    pub listen: String,
    /// The agent's build/version string.
    pub agent_version: String,
    /// Capabilities to advertise at handshake.
    pub capabilities: Vec<CapabilityInfo>,
    /// Heartbeat interval in ms (granted leases must beat at this rate).
    pub heartbeat_ms: u32,
    /// Missed heartbeats before expiry.
    pub heartbeat_budget: u32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8400".into(),
            agent_version: format!("conwrt-agent {}", env!("CARGO_PKG_VERSION")),
            capabilities: Vec::new(),
            heartbeat_ms: 1000,
            heartbeat_budget: 3,
        }
    }
}

/// Shared agent state — survives connections.
#[derive(Debug, Default)]
pub struct AgentState {
    /// The lease table.
    pub leases: LeaseTable,
    /// Stream stores: transfer_id → received bytes.
    pub streams: BTreeMap<u64, Vec<u8>>,
    /// Expected total sizes per transfer.
    pub stream_totals: BTreeMap<u64, u64>,
    /// Owning controller per transfer id (#164 P1 4272448227): first
    /// chunk claims the id; chunks from a DIFFERENT controller while
    /// the owner is still connected are refused (TransferConflict).
    /// The claim ends with the owner's CONNECTION (not the transfer):
    /// a takeover after a disconnect is the documented resume pattern
    /// (the e2e kill-and-resume reconnects under a new controller id
    /// and continues from the contiguous offset) — resume and hostile
    /// takeover are indistinguishable at the wire, so the guarantee is
    /// "no LIVE cross-controller interleave", enforced by sequential
    /// connection serving + this map.
    pub stream_owners: BTreeMap<u64, String>,
    /// Expiry events produced by the heartbeat ticker, drained by the
    /// active connection after each response (#164 P1 4272448155 —
    /// before the ticker existed, lease budgets NEVER decremented at
    /// runtime: a dead controller's lease outlived the agent).
    pub pending_events: Vec<crate::protocol::LeaseExpired>,
}

/// Errors from running the agent.
#[derive(Debug)]
pub enum AgentError {
    /// Failed to bind the listener.
    Bind(std::io::Error),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Bind(e) => write!(f, "cannot bind: {e}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// Run the agent until the process exits. Blocks forever.
///
/// # Errors
/// Fails only if the initial bind fails.
pub async fn run_agent(config: AgentConfig) -> Result<(), AgentError> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(AgentError::Bind)?;
    let state = Arc::new(Mutex::new(AgentState::default()));
    run_agent_on(listener, state, Arc::new(config)).await;
    Ok(())
}

/// Run the agent on a pre-bound listener (tests pass one to avoid the
/// bind-drop-rebind race).
pub async fn run_agent_on(
    listener: TcpListener,
    state: Arc<Mutex<AgentState>>,
    config: Arc<AgentConfig>,
) {
    // Heartbeat ticker (#164 P1 4272448155): lease budgets decrement on
    // a TIMER, not on request traffic — expiry is what frees a dead
    // controller's lease. Events land in pending_events; the active
    // connection drains them after each response it sends.
    {
        let state = Arc::clone(&state);
        let period = core::time::Duration::from_millis(config.heartbeat_ms.max(1).into());
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            loop {
                ticker.tick().await;
                let expired = {
                    let mut s = state.lock().unwrap();
                    s.leases.tick()
                };
                if !expired.is_empty() {
                    let mut s = state.lock().unwrap();
                    s.pending_events.extend(expired);
                }
            }
        });
    }

    loop {
        let (socket, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let state = Arc::clone(&state);
        let cfg = Arc::clone(&config);
        // Sequential: one controller at a time (per-connection state model).
        if let Err(e) = handle_connection(socket, state, cfg).await {
            eprintln!("[agent] connection ended: {e}");
        }
    }
}

/// Handle one controller connection to completion (EOF or error).
async fn handle_connection(
    socket: TcpStream,
    state: Arc<Mutex<AgentState>>,
    config: Arc<AgentConfig>,
) -> std::io::Result<()> {
    let (mut rx, tx) = socket.into_split();
    let mut sender = CobsSender::new(tx);
    let mut receiver = CobsReceiver::new();
    let mut handshaked = false;
    let mut controller_id = String::new();

    while let Some(frame_bytes) = receiver.receive(&mut rx).await? {
        let Ok(frame) = decode_frame(&frame_bytes) else {
            continue; // Malformed frame: skip (COBS resync at the next delimiter)
        };
        let WireFrame::Request { id, endpoint } = frame else {
            continue; // We only expect requests from the controller
        };

        // Handshake is the only pre-handshake endpoint.
        if let WireEndpoint::Handshake(req) = &endpoint {
            controller_id = req.controller_id.clone();
        }
        if !handshaked && !matches!(endpoint, WireEndpoint::Handshake(_)) {
            let _ = send_response(
                &mut sender,
                id,
                WireResult::Error(crate::dispatch::WireError::NotHandshaked),
            )
            .await;
            continue;
        }

        let result = dispatch_request(endpoint, &state, &config, &controller_id).await;
        if matches!(result, WireResult::Handshake(Ok(_))) {
            handshaked = true;
        }
        send_response(&mut sender, id, result).await?;
        // Deliver any expiry events the ticker produced since the last
        // frame (unsolicited, one event frame each).
        let pending = std::mem::take(&mut state.lock().unwrap().pending_events);
        for ev in pending {
            let frame = WireFrame::Event(AgentEvent::LeaseExpired(ev));
            sender
                .send(&encode_frame(&frame).map_err(std::io::Error::other)?)
                .await?;
        }
    }
    // Connection end: this controller's transfer CLAIMS end with it —
    // streams/bytes persist (resume semantics), but a fresh connection
    // may re-claim the ids (#164 4272448227 boundary).
    state
        .lock()
        .unwrap()
        .stream_owners
        .retain(|_, owner| owner != &controller_id);
    Ok(())
}

async fn send_response(
    sender: &mut CobsSender,
    id: u32,
    result: WireResult,
) -> std::io::Result<()> {
    let frame = WireFrame::Response { id, result };
    sender
        .send(&encode_frame(&frame).map_err(std::io::Error::other)?)
        .await
}

/// Dispatch a request to the agent state, producing the response.
async fn dispatch_request(
    endpoint: WireEndpoint,
    state: &Arc<Mutex<AgentState>>,
    config: &Arc<AgentConfig>,
    controller_id: &str,
) -> WireResult {
    match endpoint {
        WireEndpoint::Handshake(HandshakeRequest {
            protocol_version, ..
        }) => {
            if protocol_version != PROTOCOL_VERSION {
                return WireResult::Handshake(Err(HandshakeError::VersionMismatch {
                    agent: PROTOCOL_VERSION,
                    requested: protocol_version,
                }));
            }
            let _ = controller_id;
            WireResult::Handshake(Ok(HandshakeOk {
                protocol_version: PROTOCOL_VERSION,
                agent_version: config.agent_version.clone(),
                capabilities: config.capabilities.clone(),
            }))
        }
        WireEndpoint::Capabilities => WireResult::Capabilities(config.capabilities.clone()),
        WireEndpoint::LeaseAcquire(req) => {
            let mut s = state.lock().unwrap();
            match s.leases.acquire(
                &req.resource,
                controller_id,
                req.exclusive,
                req.on_disconnect,
                config.heartbeat_budget,
            ) {
                Ok(lease_id) => WireResult::Lease(LeaseResponse::Granted {
                    lease_id,
                    heartbeat_ms: config.heartbeat_ms,
                }),
                Err(LeaseError::Denied(LeaseDenied::HeldBy(h))) => {
                    WireResult::Lease(LeaseResponse::Denied { holder: Some(h) })
                }
                Err(_) => WireResult::Lease(LeaseResponse::Denied { holder: None }),
            }
        }
        WireEndpoint::LeaseRelease { lease_id } => {
            let mut s = state.lock().unwrap();
            // Owner-checked (#164 P1 4272448192): a controller may only
            // free its OWN lease; the refused case reads as Released(false)
            // (the wire bool carries no reason — the controller can query).
            WireResult::LeaseReleased(s.leases.release_by(lease_id, controller_id).is_ok())
        }
        WireEndpoint::Heartbeat(hb) => {
            let mut s = state.lock().unwrap();
            match s.leases.heartbeat(hb.lease_id, config.heartbeat_budget) {
                Ok(()) => WireResult::HeartbeatAcked,
                Err(_) => WireResult::Error(crate::dispatch::WireError::UnknownLease(hb.lease_id)),
            }
        }
        WireEndpoint::StreamChunk(chunk) => {
            let mut s = state.lock().unwrap();
            // Transfer-id ownership (#164 P1 4272448227): the first chunk
            // claims the id; a different controller's chunk with the same
            // id is a CONFLICT, not data — refusing beats interleaving.
            match s.stream_owners.get(&chunk.transfer_id) {
                Some(owner) if owner != controller_id => {
                    return WireResult::Error(WireError::TransferConflict {
                        transfer_id: chunk.transfer_id,
                        holder: owner.clone(),
                    });
                }
                None => {
                    s.stream_owners
                        .insert(chunk.transfer_id, controller_id.to_string());
                }
                _ => {}
            }
            // Idempotent contiguous-append (same semantics as the spike).
            let contiguous = {
                let entry = s.streams.entry(chunk.transfer_id).or_default();
                if chunk.offset as usize == entry.len() {
                    entry.extend_from_slice(&chunk.data);
                }
                entry.len() as u64
            };
            if let Some(total) = chunk.total {
                s.stream_totals.insert(chunk.transfer_id, total);
            }
            let total = s
                .stream_totals
                .get(&chunk.transfer_id)
                .copied()
                .unwrap_or(0);
            let done = total > 0 && contiguous == total;
            WireResult::StreamAck(StreamAck {
                transfer_id: chunk.transfer_id,
                contiguous,
                done,
            })
        }
        WireEndpoint::StreamStatus { transfer_id } => {
            let s = state.lock().unwrap();
            let contiguous = s.streams.get(&transfer_id).map(Vec::len).unwrap_or(0) as u64;
            let total = s.stream_totals.get(&transfer_id).copied().unwrap_or(0);
            let done = total > 0 && contiguous == total;
            WireResult::StreamAck(StreamAck {
                transfer_id,
                contiguous,
                done,
            })
        }
        // UART passthrough is the MCU agents' capability (#110); the std
        // TCP agent has no local UART hardware to sink bytes into.
        WireEndpoint::UartWrite { .. } => WireResult::Error(crate::dispatch::WireError::Internal(
            "uart passthrough unsupported on this agent".into(),
        )),
        // Same for detection sessions (#215 slice 5): they ride the MCU
        // agents' UART RX stream, which the std TCP agent does not have.
        WireEndpoint::DetectStart(_) | WireEndpoint::DetectStatus(_) => WireResult::Error(
            crate::dispatch::WireError::Internal("detect mode unsupported on this agent".into()),
        ),
    }
}
