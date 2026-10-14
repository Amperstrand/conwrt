//! Transport-independent agent core: handshake gating, capability
//! advertisement, and lease handling over the Tier-A protocol types.
//!
//! Both transports speak this logic — the std TCP agent (M3) and the MCU
//! agents (M5: USB CDC-ACM) — so controller-visible semantics stay
//! identical regardless of which side of ADR-0002's tier boundary the
//! agent runs on.

use alloc::string::String;
use alloc::vec::Vec;

use crate::dispatch::{AgentEvent, WireEndpoint, WireError, WireFrame, WireResult};
use crate::leases::{LeaseDenied, LeaseError, LeaseTable};
use crate::protocol::{
    CapabilityInfo, HandshakeError, HandshakeOk, HandshakeRequest, LeaseResponse, PROTOCOL_VERSION,
};

/// Missed-heartbeats-to-expiry budget granted per lease.
const HEARTBEAT_BUDGET: u32 = 3;

/// Heartbeat interval advertised with each grant.
const HEARTBEAT_MS: u32 = 1000;

/// The protocol state machine: what an agent IS, independent of how bytes
/// arrive (tokio TCP, USB CDC, …).
pub struct ServerCore {
    agent_version: String,
    capabilities: Vec<CapabilityInfo>,
    handshaked: bool,
    controller: Option<String>,
    leases: LeaseTable,
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
        }
    }

    /// Drop all session state — call on connection loss. Leases die with
    /// their controller (the `Abort` default); parking `Complete` work
    /// across reconnects is an M6 concern.
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
                WireResult::Error(WireError::UnknownTransfer(chunk.transfer_id))
            }
            WireEndpoint::StreamStatus { transfer_id } => {
                WireResult::Error(WireError::UnknownTransfer(transfer_id))
            }
        }
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
}
