//! The controller-side client (#108): connect to an agent, handshake,
//! exercise the protocol surface.
//!
//! Owns one TCP connection + the COBS pump. Each request sends a
//! [`WireFrame::Request`] and awaits the matching [`WireFrame::Response`]
//! (correlated by id). Events arrive interleaved and are surfaced via the
//! [`AgentClient::try_recv_event`] non-blocking call.

use std::collections::VecDeque;

use tokio::net::TcpStream;

use crate::dispatch::{
    AgentEvent, WireEndpoint, WireFrame, WireResult, decode_frame, encode_frame,
};
use crate::protocol::{
    CapabilityInfo, HandshakeError, HandshakeOk, Heartbeat, LeaseRequest, LeaseResponse, StreamAck,
    StreamChunk,
};
use crate::wire::{CobsReceiver, CobsSender};

/// Errors from the controller client.
#[derive(Debug)]
pub enum ClientError {
    /// TCP connection failed.
    Connect(std::io::Error),
    /// The connection closed mid-operation.
    Closed,
    /// Frame serialization failed (should not occur).
    Encode(postcard::Error),
    /// Frame deserialization failed (malformed agent).
    Decode(postcard::Error),
    /// I/O error on the stream.
    Io(std::io::Error),
    /// The agent returned an error result.
    Agent(crate::dispatch::WireError),
    /// Handshake version mismatch.
    Handshake(HandshakeError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect(e) => write!(f, "connect: {e}"),
            ClientError::Closed => write!(f, "connection closed"),
            ClientError::Encode(e) => write!(f, "encode: {e}"),
            ClientError::Decode(e) => write!(f, "decode: {e}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Agent(e) => write!(f, "agent error: {e:?}"),
            ClientError::Handshake(e) => write!(f, "handshake: {e:?}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A connected controller-side client.
pub struct AgentClient {
    sender: CobsSender,
    receiver: CobsReceiver,
    rx: tokio::net::tcp::OwnedReadHalf,
    next_id: u32,
    events: VecDeque<AgentEvent>,
}

impl AgentClient {
    /// Connect to an agent at `addr` (e.g. `"127.0.0.1:8400"`).
    ///
    /// # Errors
    /// TCP connect failure.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let socket = TcpStream::connect(addr)
            .await
            .map_err(ClientError::Connect)?;
        let (rx, tx) = socket.into_split();
        Ok(Self {
            sender: CobsSender::new(tx),
            receiver: CobsReceiver::new(),
            rx,
            next_id: 0,
            events: VecDeque::new(),
        })
    }

    /// Send a request and await the matching response.
    async fn round_trip(&mut self, endpoint: WireEndpoint) -> Result<WireResult, ClientError> {
        self.next_id += 1;
        let id = self.next_id;
        let frame = WireFrame::Request { id, endpoint };
        self.sender
            .send(&encode_frame(&frame).map_err(ClientError::Encode)?)
            .await
            .map_err(ClientError::Io)?;

        loop {
            let bytes = self
                .receiver
                .receive(&mut self.rx)
                .await
                .map_err(ClientError::Io)?
                .ok_or(ClientError::Closed)?;
            match decode_frame(&bytes).map_err(ClientError::Decode)? {
                WireFrame::Response { id: rid, result } if rid == id => return Ok(result),
                WireFrame::Event(ev) => {
                    self.events.push_back(ev);
                }
                _ => continue, // response to a stale request or unexpected frame
            }
        }
    }

    /// Handshake; returns the agent's capabilities.
    ///
    /// # Errors
    /// Version mismatch or transport failure.
    pub async fn handshake(
        &mut self,
        controller_id: &str,
    ) -> Result<Vec<CapabilityInfo>, ClientError> {
        let result = self
            .round_trip(WireEndpoint::Handshake(crate::protocol::HandshakeRequest {
                protocol_version: crate::protocol::PROTOCOL_VERSION,
                controller_id: controller_id.into(),
            }))
            .await?;
        match result {
            WireResult::Handshake(Ok(HandshakeOk { capabilities, .. })) => Ok(capabilities),
            WireResult::Handshake(Err(e)) => Err(ClientError::Handshake(e)),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type for handshake".into(),
            ))),
        }
    }

    /// List capabilities.
    ///
    /// # Errors
    /// Transport failure or agent error.
    pub async fn capabilities(&mut self) -> Result<Vec<CapabilityInfo>, ClientError> {
        match self.round_trip(WireEndpoint::Capabilities).await? {
            WireResult::Capabilities(caps) => Ok(caps),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Acquire a lease.
    ///
    /// # Errors
    /// Transport failure, denial, or agent error.
    pub async fn acquire_lease(
        &mut self,
        request: LeaseRequest,
    ) -> Result<LeaseResponse, ClientError> {
        match self.round_trip(WireEndpoint::LeaseAcquire(request)).await? {
            WireResult::Lease(resp) => Ok(resp),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Release a lease.
    ///
    /// # Errors
    /// Transport failure or agent error.
    pub async fn release_lease(&mut self, lease_id: u64) -> Result<bool, ClientError> {
        match self
            .round_trip(WireEndpoint::LeaseRelease { lease_id })
            .await?
        {
            WireResult::LeaseReleased(ok) => Ok(ok),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Send a heartbeat.
    ///
    /// # Errors
    /// Transport failure or agent error.
    pub async fn heartbeat(&mut self, lease_id: u64) -> Result<(), ClientError> {
        match self
            .round_trip(WireEndpoint::Heartbeat(Heartbeat { lease_id }))
            .await?
        {
            WireResult::HeartbeatAcked => Ok(()),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Write bytes to a UART port (lease-gated agent-side, M5 #110).
    /// Incoming UART bytes arrive unsolicited as `AgentEvent::UartData`
    /// via [`AgentClient::try_recv_event`].
    ///
    /// # Errors
    /// Transport failure, missing lease (`LeaseRequired`), or agent error.
    pub async fn uart_write(&mut self, port: u8, data: Vec<u8>) -> Result<usize, ClientError> {
        match self
            .round_trip(WireEndpoint::UartWrite { port, data })
            .await?
        {
            WireResult::UartWritten(n) => Ok(n),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Send one stream chunk and await its ack (lock-step backpressure).
    ///
    /// # Errors
    /// Transport failure or agent error.
    pub async fn send_chunk(&mut self, chunk: StreamChunk) -> Result<StreamAck, ClientError> {
        match self.round_trip(WireEndpoint::StreamChunk(chunk)).await? {
            WireResult::StreamAck(ack) => Ok(ack),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Query a transfer's status (the resume token).
    ///
    /// # Errors
    /// Transport failure or agent error.
    pub async fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, ClientError> {
        match self
            .round_trip(WireEndpoint::StreamStatus { transfer_id })
            .await?
        {
            WireResult::StreamAck(ack) => Ok(ack),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Arm boot-milestone detection on a UART port (#215 slice 5);
    /// latched milestones arrive as `AgentEvent::DetectFinding` via
    /// [`AgentClient::try_recv_event`]. Returns the (fresh, empty)
    /// session report.
    ///
    /// # Errors
    /// Transport failure or agent error (no detection session armed).
    pub async fn detect_start(
        &mut self,
        port: u8,
    ) -> Result<crate::protocol::DetectReport, ClientError> {
        match self
            .round_trip(WireEndpoint::DetectStart(crate::protocol::DetectRequest {
                port,
            }))
            .await?
        {
            WireResult::Detect(report) => Ok(report),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Query a detection session's latched findings (reconnect
    /// catch-up).
    ///
    /// # Errors
    /// Transport failure or agent error (no detection session armed).
    pub async fn detect_status(
        &mut self,
        port: u8,
    ) -> Result<crate::protocol::DetectReport, ClientError> {
        match self
            .round_trip(WireEndpoint::DetectStatus(
                crate::protocol::DetectStatusQuery { port },
            ))
            .await?
        {
            WireResult::Detect(report) => Ok(report),
            WireResult::Error(e) => Err(ClientError::Agent(e)),
            _ => Err(ClientError::Agent(crate::dispatch::WireError::Internal(
                "unexpected response type".into(),
            ))),
        }
    }

    /// Non-blocking: drain any buffered unsolicited events.
    #[must_use]
    pub fn try_recv_event(&mut self) -> Option<AgentEvent> {
        self.events.pop_front()
    }
}
