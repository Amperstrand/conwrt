//! Typed wire frames and endpoint dispatch (#108).
//!
//! One COBS frame = one postcard-serialized [`WireFrame`]. Requests carry a
//! correlation id; responses echo it. The agent dispatches on the
//! [`WireEndpoint`] variant; the controller correlates on the id.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::protocol::{
    CapabilityInfo, DisconnectPolicy, HandshakeError, HandshakeOk, HandshakeRequest, Heartbeat,
    LeaseExpired, LeaseRequest, LeaseResponse, StreamAck, StreamChunk,
};

/// A request to the agent (controller → agent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireEndpoint {
    /// Open a session; negotiate versions.
    Handshake(HandshakeRequest),
    /// List exposed capabilities.
    Capabilities,
    /// Acquire a resource lease.
    LeaseAcquire(LeaseRequest),
    /// Release a lease.
    LeaseRelease {
        /// The lease to release.
        lease_id: u64,
    },
    /// Heartbeat a lease (refill its budget).
    Heartbeat(Heartbeat),
    /// Send one stream chunk (lock-step: await the ack before the next).
    StreamChunk(StreamChunk),
    /// Query a transfer's status (the resume token).
    StreamStatus {
        /// Transfer to query.
        transfer_id: u64,
    },
    /// Write bytes to a UART port (M5 #110). Requires the lease on
    /// `uart{port}`; the reply is [`WireResult::UartWritten`].
    UartWrite {
        /// Port index (0-based, as advertised in capabilities).
        port: u8,
        /// Payload bytes for the UART TX line.
        data: Vec<u8>,
    },
}

/// A response from the agent (agent → controller), correlated by id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireResult {
    /// Handshake outcome.
    Handshake(Result<HandshakeOk, HandshakeError>),
    /// Capability list.
    Capabilities(Vec<CapabilityInfo>),
    /// Lease acquire outcome.
    Lease(LeaseResponse),
    /// Lease release outcome (true = released).
    LeaseReleased(bool),
    /// Heartbeat accepted.
    HeartbeatAcked,
    /// Stream ack (contiguous offset = the resume token).
    StreamAck(StreamAck),
    /// Bytes accepted onto the UART TX line (M5 #110).
    UartWritten(usize),
    /// The endpoint errored.
    Error(WireError),
}

/// Agent-side operational errors (distinct from protocol-level refusals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireError {
    /// The lease id is unknown (expired or never held).
    UnknownLease(u64),
    /// The transfer id is unknown.
    UnknownTransfer(u64),
    /// Internal agent state error.
    Internal(String),
    /// Request sent before a successful handshake.
    NotHandshaked,
    /// The operation needs the named resource lease first (M5 #110: UART
    /// writes are lease-gated).
    LeaseRequired(String),
}

/// The wire frame: exactly one per COBS frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireFrame {
    /// Controller → agent.
    Request {
        /// Correlation id (controller-assigned, monotonically increasing).
        id: u32,
        /// The operation.
        endpoint: WireEndpoint,
    },
    /// Agent → controller.
    Response {
        /// Echoes the request id.
        id: u32,
        /// The outcome.
        result: WireResult,
    },
    /// Agent → controller, unsolicited (lease expiry, progress).
    Event(AgentEvent),
}

/// Unsolicited events from agent to controller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AgentEvent {
    /// A lease expired (heartbeat timeout).
    LeaseExpired(LeaseExpired),
    /// A Complete-policy operation finished after controller loss.
    OperationCompleted {
        /// The lease it ran under.
        lease_id: u64,
        /// Human summary.
        summary: String,
    },
    /// A lease's disconnect policy, surfaced for logging (Abort vs Complete).
    Policy {
        /// Lease id.
        lease_id: u64,
        /// The policy.
        policy: DisconnectPolicy,
    },
    /// Bytes received from a UART port (M5 #110) — unsolicited push,
    /// harvested controller-side via `AgentClient::try_recv_event`.
    UartData {
        /// Port index (0-based).
        port: u8,
        /// Payload bytes from the UART RX line.
        data: Vec<u8>,
    },
}

/// Encode a frame to bytes (postcard).
///
/// # Errors
/// Serialization failure (should not occur for these types).
pub fn encode_frame(frame: &WireFrame) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(frame)
}

/// Decode a frame from bytes (postcard).
///
/// # Errors
/// Deserialization failure (malformed frame).
pub fn decode_frame(bytes: &[u8]) -> Result<WireFrame, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_VERSION;

    #[test]
    fn handshake_request_round_trips() {
        let frame = WireFrame::Request {
            id: 1,
            endpoint: WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION,
                controller_id: "laptop".into(),
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn lease_response_round_trips() {
        let frame = WireFrame::Response {
            id: 7,
            result: WireResult::Lease(LeaseResponse::Granted {
                lease_id: 1,
                heartbeat_ms: 1000,
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn stream_chunk_round_trips() {
        let frame = WireFrame::Request {
            id: 42,
            endpoint: WireEndpoint::StreamChunk(StreamChunk {
                transfer_id: 1,
                offset: 4096,
                total: Some(1_048_576),
                data: vec![0xAB; 512],
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn error_result_round_trips() {
        let frame = WireFrame::Response {
            id: 3,
            result: WireResult::Error(WireError::UnknownLease(99)),
        };
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn event_round_trips() {
        let frame = WireFrame::Event(AgentEvent::LeaseExpired(LeaseExpired {
            lease_id: 5,
            reason: crate::protocol::LeaseExpiryReason::HeartbeatTimeout,
        }));
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn garbage_bytes_fail_cleanly() {
        assert!(decode_frame(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    }
}
