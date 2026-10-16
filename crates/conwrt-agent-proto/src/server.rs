//! Transport-independent agent core: handshake gating, capability
//! advertisement, and lease handling over the Tier-A protocol types.
//!
//! Both transports speak this logic — the std TCP agent (M3) and the MCU
//! agents (M5: USB CDC-ACM) — so controller-visible semantics stay
//! identical regardless of which side of ADR-0002's tier boundary the
//! agent runs on.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::dispatch::{AgentEvent, WireEndpoint, WireError, WireFrame, WireResult};
use crate::leases::{LeaseDenied, LeaseError, LeaseTable};
use crate::protocol::{
    CapabilityInfo, DisconnectPolicy, HandshakeError, HandshakeOk, HandshakeRequest, LeaseResponse,
    PROTOCOL_VERSION, StreamAck, StreamChunk,
};

/// Missed-heartbeats-to-expiry budget granted per lease.
const HEARTBEAT_BUDGET: u32 = 3;

/// Heartbeat interval advertised with each grant.
const HEARTBEAT_MS: u32 = 1000;

/// Where UART-bound bytes actually go — the transport-independent stand-in
/// for real UART hardware. The HIL mock records; the firmware sinks into
/// the board UART.
///
/// `Send` supertrait: keeps [`ServerCore`] `Send` so the host-side mock can
/// spawn it on tokio (the MCU runs it in a single embassy task where the
/// bound is a no-op marker).
pub trait UartSink: Send {
    /// Write `data` to `port`; returns the byte count accepted.
    ///
    /// # Errors
    /// Hardware failure or an invalid port — surfaced to the controller
    /// as a [`WireError`].
    fn uart_write(&mut self, port: u8, data: &[u8]) -> Result<usize, WireError>;
}

/// Where image-stream chunks actually go (#226 slice 1): an executor's
/// bounded transfer window. The firmware attaches a sink backed by
/// [`conwrt_executor::TransferState`] (the executor crate); host tests
/// attach mocks. Same `Send` rationale as [`UartSink`].
pub trait TransferSink: Send {
    /// Feed one chunk; the returned [`StreamAck`] carries the resume
    /// token (contiguous received bytes — see the executor crate).
    ///
    /// # Errors
    /// Window-level failures (gap, backpressure, wrong transfer) as
    /// [`WireError`] for the controller.
    fn stream_chunk(&mut self, chunk: &StreamChunk) -> Result<StreamAck, WireError>;

    /// Query a transfer's status (the resume token).
    ///
    /// # Errors
    /// [`WireError::UnknownTransfer`] when the sink tracks no such
    /// transfer.
    fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, WireError>;
}

/// The resource whose exclusive lease gates image-stream endpoints
/// (`"executor"` — the standalone-executor workflow, #226).
pub const EXECUTOR_RESOURCE: &str = "executor";

/// The protocol state machine: what an agent IS, independent of how bytes
/// arrive (tokio TCP, USB CDC, …).
pub struct ServerCore {
    agent_version: String,
    capabilities: Vec<CapabilityInfo>,
    handshaked: bool,
    controller: Option<String>,
    leases: LeaseTable,
    uart: Option<Box<dyn UartSink>>,
    transfer: Option<Box<dyn TransferSink>>,
    outbound_events: VecDeque<AgentEvent>,
}

impl ServerCore {
    /// New agent core advertising `capabilities` under `agent_version`.
    #[must_use]
    pub fn new(agent_version: &str, capabilities: Vec<CapabilityInfo>) -> Self {
        Self {
            agent_version: String::from(agent_version),
            capabilities,
            handshaked: false,
            controller: None,
            leases: LeaseTable::new(),
            uart: None,
            transfer: None,
            outbound_events: VecDeque::new(),
        }
    }

    /// New agent core with a UART sink attached (enables lease-gated
    /// `UartWrite` handling).
    #[must_use]
    pub fn with_uart(
        agent_version: &str,
        capabilities: Vec<CapabilityInfo>,
        uart: Box<dyn UartSink>,
    ) -> Self {
        let mut core = Self::new(agent_version, capabilities);
        core.uart = Some(uart);
        core
    }

    /// New agent core with an image-transfer sink attached (enables
    /// lease-gated `StreamChunk`/`StreamStatus` handling, #226 slice 1).
    #[must_use]
    pub fn with_transfer(
        agent_version: &str,
        capabilities: Vec<CapabilityInfo>,
        transfer: Box<dyn TransferSink>,
    ) -> Self {
        let mut core = Self::new(agent_version, capabilities);
        core.transfer = Some(transfer);
        core
    }

    /// Drop all session state — call on connection loss. Leases die with
    /// their controller (the `Abort` default); parking `Complete` work
    /// across reconnects is an M6 concern. Queued outbound events SURVIVE:
    /// they are agent output, not controller state (a boot banner queued
    /// before a connection still delivers on connect).
    pub fn reset_session(&mut self) {
        self.handshaked = false;
        self.controller = None;
        self.leases = LeaseTable::new();
    }

    /// Handle one decoded frame; `Some(response)` when the frame was a
    /// Request. Responses and Events from a controller are ignored.
    #[must_use]
    pub fn handle_frame(&mut self, frame: WireFrame) -> Option<WireFrame> {
        match frame {
            WireFrame::Request { id, endpoint } => Some(WireFrame::Response {
                id,
                result: self.handle_endpoint(endpoint),
            }),
            WireFrame::Response { .. } | WireFrame::Event(_) => None,
        }
    }

    fn handle_endpoint(&mut self, endpoint: WireEndpoint) -> WireResult {
        if !self.handshaked && !matches!(endpoint, WireEndpoint::Handshake(_)) {
            return WireResult::Error(WireError::NotHandshaked);
        }
        match endpoint {
            WireEndpoint::Handshake(HandshakeRequest {
                protocol_version,
                controller_id,
            }) => {
                if protocol_version != PROTOCOL_VERSION {
                    return WireResult::Handshake(Err(HandshakeError::VersionMismatch {
                        agent: PROTOCOL_VERSION,
                        requested: protocol_version,
                    }));
                }
                self.handshaked = true;
                self.controller = Some(controller_id);
                WireResult::Handshake(Ok(HandshakeOk {
                    protocol_version: PROTOCOL_VERSION,
                    agent_version: self.agent_version.clone(),
                    capabilities: self.capabilities.clone(),
                }))
            }
            WireEndpoint::Capabilities => WireResult::Capabilities(self.capabilities.clone()),
            WireEndpoint::LeaseAcquire(req) => {
                // #226 lease semantics: an in-flight recovery POST must
                // survive controller loss (the one-request window cannot
                // be aborted mid-body) — executor leases are exclusive
                // and Complete-policy only, refused at acquisition
                // (review rounds 4+5).
                if req.resource == EXECUTOR_RESOURCE {
                    if !req.exclusive {
                        return WireResult::Error(WireError::Internal(String::from(
                            "executor leases are exclusive-only",
                        )));
                    }
                    if req.on_disconnect != DisconnectPolicy::Complete {
                        return WireResult::Error(WireError::Internal(String::from(
                            "executor leases require Complete disconnect policy",
                        )));
                    }
                }
                let controller = self.controller.clone().unwrap_or_default();
                match self.leases.acquire(
                    &req.resource,
                    &controller,
                    req.exclusive,
                    req.on_disconnect,
                    HEARTBEAT_BUDGET,
                ) {
                    Ok(_) => WireResult::Lease(LeaseResponse::Granted {
                        heartbeat_ms: HEARTBEAT_MS,
                    }),
                    Err(LeaseError::Denied(LeaseDenied::HeldBy(holder))) => {
                        WireResult::Lease(LeaseResponse::Denied {
                            holder: Some(holder),
                        })
                    }
                    Err(LeaseError::Denied(LeaseDenied::AlreadyHeld)) => {
                        WireResult::Lease(LeaseResponse::Denied {
                            holder: self.controller.clone(),
                        })
                    }
                    Err(LeaseError::UnknownLease(id)) => {
                        WireResult::Error(WireError::UnknownLease(id))
                    }
                }
            }
            WireEndpoint::LeaseRelease { lease_id } => match self.leases.release(lease_id) {
                Ok(_) => WireResult::LeaseReleased(true),
                Err(LeaseError::UnknownLease(id)) => WireResult::Error(WireError::UnknownLease(id)),
                Err(_) => WireResult::LeaseReleased(false),
            },
            WireEndpoint::Heartbeat(hb) => match self
                .leases
                .heartbeat(hb.lease_id, HEARTBEAT_BUDGET)
            {
                Ok(()) => WireResult::HeartbeatAcked,
                Err(LeaseError::UnknownLease(id)) => WireResult::Error(WireError::UnknownLease(id)),
                Err(_) => WireResult::Error(WireError::Internal(String::from("heartbeat refused"))),
            },
            WireEndpoint::StreamChunk(chunk) => {
                // sink presence first: bare cores keep their historical
                // UnknownTransfer contract (review round 4)
                if self.transfer.is_none() {
                    return WireResult::Error(WireError::UnknownTransfer(chunk.transfer_id));
                }
                if !self.holds_exclusive(EXECUTOR_RESOURCE) {
                    return WireResult::Error(WireError::LeaseRequired(String::from(
                        EXECUTOR_RESOURCE,
                    )));
                }
                match self.transfer.as_mut() {
                    Some(sink) => match sink.stream_chunk(&chunk) {
                        Ok(ack) => WireResult::StreamAck(ack),
                        Err(e) => WireResult::Error(e),
                    },
                    None => WireResult::Error(WireError::UnknownTransfer(chunk.transfer_id)),
                }
            }
            WireEndpoint::StreamStatus { transfer_id } => {
                if self.transfer.is_none() {
                    return WireResult::Error(WireError::UnknownTransfer(transfer_id));
                }
                if !self.holds_exclusive(EXECUTOR_RESOURCE) {
                    return WireResult::Error(WireError::LeaseRequired(String::from(
                        EXECUTOR_RESOURCE,
                    )));
                }
                match self.transfer.as_mut() {
                    Some(sink) => match sink.stream_status(transfer_id) {
                        Ok(ack) => WireResult::StreamAck(ack),
                        Err(e) => WireResult::Error(e),
                    },
                    None => WireResult::Error(WireError::UnknownTransfer(transfer_id)),
                }
            }
            WireEndpoint::UartWrite { port, data } => {
                let resource = alloc::format!("uart{port}");
                if !self.holds_resource(&resource) {
                    return WireResult::Error(WireError::LeaseRequired(resource));
                }
                match self.uart.as_mut() {
                    Some(sink) => match sink.uart_write(port, &data) {
                        Ok(n) => WireResult::UartWritten(n),
                        Err(e) => WireResult::Error(e),
                    },
                    None => WireResult::Error(WireError::Internal(String::from(
                        "no uart sink attached",
                    ))),
                }
            }
        }
    }

    /// Whether the current controller holds any lease on `resource`
    /// (the gate for UART writes, M5 #110).
    fn holds_resource(&self, resource: &str) -> bool {
        let controller = self.controller.clone().unwrap_or_default();
        self.leases
            .leases()
            .any(|lease| lease.resource == resource && lease.controller == controller)
    }

    /// Whether the current controller holds an **exclusive** lease on
    /// `resource` — the stricter gate for image-stream endpoints
    /// (#226: the executor resource is exclusive-only; review round 1).
    fn holds_exclusive(&self, resource: &str) -> bool {
        let controller = self.controller.clone().unwrap_or_default();
        self.leases.leases().any(|lease| {
            lease.resource == resource && lease.controller == controller && lease.exclusive
        })
    }

    /// Advance lease expiry by one heartbeat interval; returns the expiry
    /// events to emit. The caller owns the clock (ADR-0002: time is a
    /// capability).
    #[must_use]
    pub fn tick(&mut self) -> Vec<AgentEvent> {
        self.leases
            .tick()
            .into_iter()
            .map(AgentEvent::LeaseExpired)
            .collect()
    }

    /// Queue unsolicited UART RX bytes for the controller (the firmware's
    /// UART receive task calls this). Delivery is via [`ServerCore::take_events`]
    /// on the transport's next drain.
    pub fn push_uart_data(&mut self, port: u8, data: &[u8]) {
        self.outbound_events.push_back(AgentEvent::UartData {
            port,
            data: Vec::from(data),
        });
    }

    /// Drain queued outbound events; the transport sends each as one frame.
    #[must_use]
    pub fn take_events(&mut self) -> Vec<AgentEvent> {
        self.outbound_events.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        DisconnectPolicy, LeaseExpired as LeaseExpiredShape, LeaseExpiryReason,
        LeaseRequest as LeaseRequestShape,
    };

    fn core() -> ServerCore {
        ServerCore::new(
            "test-agent 0.1",
            alloc::vec![CapabilityInfo {
                name: String::from("serial"),
                detail: alloc::vec![(String::from("uarts"), String::from("1"))],
            }],
        )
    }

    fn handshake(core: &mut ServerCore) -> WireResult {
        core.handle_frame(WireFrame::Request {
            id: 1,
            endpoint: WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION,
                controller_id: String::from("laptop"),
            }),
        })
        .map(|f| match f {
            WireFrame::Response { result, .. } => result,
            _ => unreachable!("handshake must answer with a Response"),
        })
        .unwrap()
    }

    fn request(core: &mut ServerCore, id: u32, endpoint: WireEndpoint) -> WireResult {
        core.handle_frame(WireFrame::Request { id, endpoint })
            .map(|f| match f {
                WireFrame::Response { result, .. } => result,
                _ => unreachable!("requests must answer with a Response"),
            })
            .unwrap()
    }

    #[test]
    fn requests_before_handshake_are_refused() {
        let mut c = core();
        let result = request(&mut c, 1, WireEndpoint::Capabilities);
        assert_eq!(
            result,
            WireResult::Error(WireError::NotHandshaked),
            "pre-handshake request must be refused"
        );
    }

    #[test]
    fn version_mismatch_is_structured() {
        let mut c = core();
        let result = request(
            &mut c,
            1,
            WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION.wrapping_add(1),
                controller_id: String::from("future-laptop"),
            }),
        );
        assert_eq!(
            result,
            WireResult::Handshake(Err(HandshakeError::VersionMismatch {
                agent: PROTOCOL_VERSION,
                requested: PROTOCOL_VERSION.wrapping_add(1),
            }))
        );
        assert!(!c.handshaked, "failed handshake must not open the session");
    }

    #[test]
    fn handshake_advertises_capabilities() {
        let mut c = core();
        let WireResult::Handshake(Ok(ok)) = handshake(&mut c) else {
            panic!("matching version must handshake");
        };
        assert_eq!(ok.capabilities.len(), 1);
        assert_eq!(ok.capabilities[0].name, "serial");
    }

    #[test]
    fn lease_lifecycle_grant_conflict_release() {
        let mut c = core();
        handshake(&mut c);

        let granted = request(
            &mut c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
        assert!(matches!(
            granted,
            WireResult::Lease(LeaseResponse::Granted { heartbeat_ms: 1000 })
        ));

        let conflict = request(
            &mut c,
            3,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
        let WireResult::Lease(LeaseResponse::Denied { holder }) = conflict else {
            panic!("exclusive conflict must be denied");
        };
        assert_eq!(holder.as_deref(), Some("laptop"));

        let released = request(&mut c, 4, WireEndpoint::LeaseRelease { lease_id: 1 });
        assert_eq!(released, WireResult::LeaseReleased(true));

        let regrant = request(
            &mut c,
            5,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
        assert!(matches!(
            regrant,
            WireResult::Lease(LeaseResponse::Granted { .. })
        ));
    }

    #[test]
    fn tick_expires_silent_lease() {
        let mut c = core();
        handshake(&mut c);
        request(
            &mut c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );

        let mut events = alloc::vec![];
        for _ in 0..HEARTBEAT_BUDGET {
            events.extend(c.tick());
        }
        assert_eq!(events.len(), 1, "budget missed heartbeats must expire");
        assert!(matches!(
            events[0],
            AgentEvent::LeaseExpired(LeaseExpiredShape {
                lease_id: 1,
                reason: LeaseExpiryReason::HeartbeatTimeout
            })
        ));
    }

    #[test]
    fn reset_session_clears_leases_and_gate() {
        let mut c = core();
        handshake(&mut c);
        request(
            &mut c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
        c.reset_session();
        assert!(
            !c.handshaked,
            "reset must close the session for the next controller"
        );
        let refused = request(&mut c, 3, WireEndpoint::Capabilities);
        assert_eq!(refused, WireResult::Error(WireError::NotHandshaked));
    }

    type SharedWrites = std::sync::Arc<std::sync::Mutex<Vec<(u8, Vec<u8>)>>>;

    struct RecordingSink {
        written: SharedWrites,
    }

    impl UartSink for RecordingSink {
        fn uart_write(&mut self, port: u8, data: &[u8]) -> Result<usize, WireError> {
            self.written.lock().unwrap().push((port, data.to_vec()));
            Ok(data.len())
        }
    }

    fn uart_core() -> (ServerCore, SharedWrites) {
        let written: SharedWrites = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let core = ServerCore::with_uart(
            "test-agent 0.1",
            Vec::new(),
            Box::new(RecordingSink {
                written: std::sync::Arc::clone(&written),
            }),
        );
        (core, written)
    }

    fn lease_uart0(c: &mut ServerCore) {
        request(
            c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from("uart0"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
    }

    #[test]
    fn uart_write_without_lease_is_refused() {
        let (mut c, written) = uart_core();
        handshake(&mut c);
        let result = request(
            &mut c,
            3,
            WireEndpoint::UartWrite {
                port: 0,
                data: Vec::from(&b"AT\r"[..]),
            },
        );
        assert_eq!(
            result,
            WireResult::Error(WireError::LeaseRequired(String::from("uart0")))
        );
        assert!(
            written.lock().unwrap().is_empty(),
            "refused write must not reach the sink"
        );
    }

    #[test]
    fn uart_write_with_lease_reaches_sink() {
        let (mut c, written) = uart_core();
        handshake(&mut c);
        lease_uart0(&mut c);
        let result = request(
            &mut c,
            3,
            WireEndpoint::UartWrite {
                port: 0,
                data: Vec::from(&b"AT\r"[..]),
            },
        );
        assert_eq!(result, WireResult::UartWritten(3));
        assert_eq!(*written.lock().unwrap(), vec![(0u8, b"AT\r".to_vec())]);
    }

    /// Recording transfer sink for the executor-stream dispatch tests.
    struct RecordingTransferSink {
        acks: Vec<StreamAck>,
    }

    impl TransferSink for RecordingTransferSink {
        fn stream_chunk(&mut self, chunk: &StreamChunk) -> Result<StreamAck, WireError> {
            let contiguous = chunk.offset + chunk.data.len() as u64;
            let ack = StreamAck {
                transfer_id: chunk.transfer_id,
                contiguous,
                done: chunk.total.is_some_and(|t| t == contiguous),
            };
            self.acks.push(ack);
            Ok(ack)
        }
        fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, WireError> {
            Err(WireError::UnknownTransfer(transfer_id))
        }
    }

    fn transfer_core() -> (ServerCore, &'static str) {
        // leak-free enough for tests: the sink is owned by the core
        let core = ServerCore::with_transfer(
            "test-agent 0.1",
            alloc::vec![],
            Box::new(RecordingTransferSink {
                acks: alloc::vec![],
            }),
        );
        (core, "executor")
    }

    fn lease_executor(core: &mut ServerCore) {
        request(
            core,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from(EXECUTOR_RESOURCE),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Complete,
            }),
        );
    }

    fn sample_chunk() -> StreamChunk {
        StreamChunk {
            transfer_id: 42,
            offset: 0,
            total: Some(3),
            data: Vec::from(&b"abc"[..]),
        }
    }

    #[test]
    fn stream_chunk_without_lease_is_refused() {
        let (mut c, _) = transfer_core();
        handshake(&mut c);
        let result = request(&mut c, 3, WireEndpoint::StreamChunk(sample_chunk()));
        assert_eq!(
            result,
            WireResult::Error(WireError::LeaseRequired(String::from("executor")))
        );
    }

    #[test]
    fn executor_shared_lease_refused_at_acquisition() {
        // #226: the executor resource is exclusive-only (review round 5)
        let (mut c, _) = transfer_core();
        handshake(&mut c);
        let result = request(
            &mut c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from(EXECUTOR_RESOURCE),
                exclusive: false,
                on_disconnect: DisconnectPolicy::Complete,
            }),
        );
        assert!(matches!(
            result,
            WireResult::Error(WireError::Internal(msg)) if msg.contains("exclusive-only")
        ));
    }

    #[test]
    fn stream_chunk_with_lease_reaches_sink_and_acks() {
        let (mut c, _) = transfer_core();
        handshake(&mut c);
        lease_executor(&mut c);
        let result = request(&mut c, 3, WireEndpoint::StreamChunk(sample_chunk()));
        assert_eq!(
            result,
            WireResult::StreamAck(StreamAck {
                transfer_id: 42,
                contiguous: 3,
                done: true,
            })
        );
    }

    #[test]
    fn stream_status_with_lease_routes_to_sink() {
        let (mut c, _) = transfer_core();
        handshake(&mut c);
        lease_executor(&mut c);
        let result = request(&mut c, 3, WireEndpoint::StreamStatus { transfer_id: 42 });
        assert_eq!(result, WireResult::Error(WireError::UnknownTransfer(42)));
    }

    #[test]
    fn stream_chunk_without_sink_stays_unknown_transfer() {
        // pre-#226 contract preserved: no sink attached -> UnknownTransfer,
        // lease gate not even consulted (review round 4)
        let mut c = core();
        handshake(&mut c);
        let result = request(&mut c, 3, WireEndpoint::StreamChunk(sample_chunk()));
        assert_eq!(result, WireResult::Error(WireError::UnknownTransfer(42)));
    }

    #[test]
    fn executor_lease_with_abort_policy_is_refused() {
        let (mut c, _) = transfer_core();
        handshake(&mut c);
        let result = request(
            &mut c,
            2,
            WireEndpoint::LeaseAcquire(LeaseRequestShape {
                resource: String::from(EXECUTOR_RESOURCE),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Abort,
            }),
        );
        assert!(matches!(
            result,
            WireResult::Error(WireError::Internal(msg))
                if msg.contains("Complete disconnect policy")
        ));
    }

    #[test]
    fn uart_events_queue_drain_and_survive_reset() {
        let (mut c, _written) = uart_core();
        c.push_uart_data(0, b"boot banner");
        c.reset_session();
        let events = c.take_events();
        assert_eq!(events.len(), 1, "queued event must survive reset_session");
        assert!(matches!(
            &events[0],
            AgentEvent::UartData { port: 0, data } if data == b"boot banner"
        ));
        assert!(
            c.take_events().is_empty(),
            "drain must empty the queue exactly once"
        );
    }
}
