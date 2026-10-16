//! # conwrt-agent-io
//!
//! The transport-session layer shared by every MCU agent firmware
//! (#215): [`ServerCore`] behind two byte pipes.
//!
//! Both firmware transports started as copy-pasted loops — the packet
//! loop (CDC read → [`CobsPump`] → [`ServerCore`] → packetized write,
//! #110/#111) and the std TCP pump in `conwrt-agent-proto` (#215 slice 3
//! twins it here for no_std). [`PacketIo`] covers packet-shaped pipes
//! (embassy-usb CDC-ACM); [`StreamIo`] covers byte streams (embassy-net
//! TCP). Owning both traits (AFIT per ADR-0002) instead of depending on
//! `embedded-io-async` in the public surface sidesteps its version-split
//! trap in mixed embassy-version dependency graphs.
//!
//! Host tests drive both session loops without hardware: in-memory mocks
//! pin the loop semantics (ADR-0011 ring 1), and the HIL parity suite
//! runs the real `AgentClient` against [`agent_session_stream`] over a
//! localhost socket — the same scenarios the std pump's own HIL suite
//! runs, so a controller cannot tell the twins apart.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

use conwrt_agent_proto::cobs::{CobsPump, encode_frame as cobs_encode};
use conwrt_agent_proto::dispatch::{WireFrame, decode_frame, encode_frame};
use conwrt_agent_proto::server::ServerCore;

use embassy_futures::select::{Either, select};

/// Full-speed USB bulk max packet size (the common CDC case).
pub const CDC_FS_PACKET: usize = 64;

/// A packet-shaped byte pipe: one call moves at most one USB bulk packet.
///
/// `embassy_usb::class::cdc_acm::CdcAcmClass` matches this shape on every
/// HAL (STM32 OTG, ESP32-S3 OTG); firmware apps implement the trait in a
/// few lines. Reads return `Ok(0)` only for empty packets — a transport
/// error is the disconnect signal that ends the session.
// AFIT per ADR-0002 (executor-agnostic, firmware monomorphizes statically;
// Send bounds are unnecessary — same trade embassy itself makes).
#[allow(async_fn_in_trait)]
pub trait PacketIo {
    /// Transport error type (mapped by the firmware impl).
    type Error;

    /// Read one packet (up to `buf.len()`); returns bytes read.
    ///
    /// # Errors
    /// Transport failure — the caller ends the session.
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write exactly one packet-sized chunk (`data.len()` ≤ max packet).
    ///
    /// # Errors
    /// Transport failure — the caller ends the session.
    async fn write_packet(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

/// One connection session of the agent: pump COBS frames from `io` through
/// `server`, write every response back packetized. Returns when the pipe
/// errors (host unplug, port close) — the caller owns reconnection and
/// session reset (connection lifecycle drives lease lifecycle, #110).
pub async fn agent_session<T: PacketIo>(io: &mut T, server: &mut ServerCore, max_packet: usize) {
    let mut buf = [0u8; CDC_FS_PACKET];
    let mut pump = CobsPump::new();
    loop {
        let Ok(n) = io.read_packet(&mut buf).await else {
            return;
        };
        pump.feed(&buf[..n]);
        while let Some(frame) = pump.pop_frame() {
            let Some(response) = decode_frame(&frame)
                .ok()
                .and_then(|decoded| server.handle_frame(decoded))
            else {
                continue;
            };
            if let Ok(bytes) = encode_frame(&response) {
                write_packetized(io, &cobs_encode(&bytes), max_packet).await;
            }
        }
    }
}

/// Packetized bulk write: chunk to `max_packet` and append a zero-length
/// packet when the frame ends exactly on a packet boundary (the host cannot
/// tell "done" from "more coming" otherwise).
pub async fn write_packetized<T: PacketIo>(io: &mut T, data: &[u8], max_packet: usize) {
    for chunk in data.chunks(max_packet) {
        if io.write_packet(chunk).await.is_err() {
            return;
        }
    }
    if !data.is_empty() && data.len() % max_packet == 0 {
        let _ = io.write_packet(&[]).await;
    }
}

/// Read chunk size for [`agent_session_stream`]. Streams impose no packet
/// shape, so any size works; 256 keeps the session's stack footprint
/// trivial on MCU while amortizing syscall/socket reads on hosts.
const STREAM_READ_BUF: usize = 256;

/// A byte-stream pipe: the TCP twin of [`PacketIo`]. Reads return
/// arbitrary chunk sizes (`Ok(0)` is end-of-stream), writes may be
/// partial. A transport error or end-of-stream is the disconnect signal
/// that ends the session.
// AFIT per ADR-0002, same trade as [`PacketIo`].
#[allow(async_fn_in_trait)]
pub trait StreamIo {
    /// Transport error type (mapped by the firmware impl).
    type Error;

    /// Read one chunk (up to `buf.len()`); `Ok(0)` = the peer closed the
    /// stream.
    ///
    /// # Errors
    /// Transport failure — the caller ends the session.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write bytes; may write fewer than requested (callers loop, see
    /// [`write_all_stream`]).
    ///
    /// # Errors
    /// Transport failure — the caller ends the session.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
}

/// One connection session of the agent over a byte stream — the no_std
/// twin of `conwrt-agent-proto`'s std TCP pump (#215 slice 3): pump COBS
/// frames from `io` through `server`, reply to every request, and drain
/// queued events after each reply. Wire-identical semantics to the std
/// agent, so a controller cannot tell them apart; with
/// [`ServerCore::push_uart_data`] fed by the firmware's UART task, any
/// MCU agent is Ethernet-attachable (controller ←LAN→ agent ←UART→
/// router). Returns on transport error or end-of-stream; the caller owns
/// reconnection and session reset (connection lifecycle drives lease
/// lifecycle, #110).
pub async fn agent_session_stream<T: StreamIo>(io: &mut T, server: &mut ServerCore) {
    let mut buf = [0u8; STREAM_READ_BUF];
    let mut pump = CobsPump::new();
    loop {
        let Ok(n) = io.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        pump.feed(&buf[..n]);
        while let Some(frame) = pump.pop_frame() {
            let Some(response) = decode_frame(&frame)
                .ok()
                .and_then(|decoded| server.handle_frame(decoded))
            else {
                continue;
            };
            if let Ok(bytes) = encode_frame(&response) {
                write_all_stream(io, &cobs_encode(&bytes)).await;
            }
            send_pending_events(io, server).await;
        }
    }
}

/// Stream-write `data` fully, looping over partial writes (the packet
/// twin is [`write_packetized`]; streams have no packet discipline).
/// Returns on the first transport error or a zero-byte write (stalled
/// peer).
pub async fn write_all_stream<T: StreamIo>(io: &mut T, data: &[u8]) {
    let mut sent = 0;
    while sent < data.len() {
        match io.write(&data[sent..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => sent += n,
        }
    }
}

/// Drain events queued on `server` (e.g. UART RX pushed by another task)
/// to the controller — after each reply, mirroring the std pump.
async fn send_pending_events<T: StreamIo>(io: &mut T, server: &mut ServerCore) {
    for event in server.take_events() {
        if let Ok(bytes) = encode_frame(&WireFrame::Event(event)) {
            write_all_stream(io, &cobs_encode(&bytes)).await;
        }
    }
}

/// UART RX chunk size for [`agent_session_stream_events`] — console lines,
/// not bulk data.
const EVENT_BUF: usize = 64;

/// An out-of-band data source feeding the agent's event queue: the
/// firmware's UART RX half, a channel in host tests. Implementations
/// backing `wait_data` MUST be cancel-safe (the session selects them
/// against stream reads and drops the loser mid-await).
// AFIT per ADR-0002, same trade as [`PacketIo`]/[`StreamIo`].
#[allow(async_fn_in_trait)]
pub trait EventSource {
    /// Transport error type.
    type Error;

    /// Wait for data; fills `buf`, returns bytes read. `Ok(0)` ends the
    /// session (source closed).
    ///
    /// # Errors
    /// Transport failure — the caller ends the session.
    async fn wait_data(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// [`agent_session_stream`] plus a live event source: the firmware
/// shape (#215 slice 4) — controller frames on the stream, UART RX from
/// [`EventSource`], both driving one [`ServerCore`]. Events flow to the
/// controller as they arrive (not just after replies), so a passively
/// listening controller sees a boot banner without sending anything.
/// Returns when either side errors or reaches end-of-stream; the caller
/// owns reconnection and session reset.
pub async fn agent_session_stream_events<T: StreamIo, E: EventSource>(
    io: &mut T,
    events: &mut E,
    server: &mut ServerCore,
) {
    let mut buf = [0u8; STREAM_READ_BUF];
    let mut evbuf = [0u8; EVENT_BUF];
    let mut pump = CobsPump::new();
    loop {
        match select(io.read(&mut buf), events.wait_data(&mut evbuf)).await {
            Either::First(read) => {
                let Ok(n) = read else {
                    return;
                };
                if n == 0 {
                    return;
                }
                pump.feed(&buf[..n]);
                while let Some(frame) = pump.pop_frame() {
                    let Some(response) = decode_frame(&frame)
                        .ok()
                        .and_then(|decoded| server.handle_frame(decoded))
                    else {
                        continue;
                    };
                    if let Ok(bytes) = encode_frame(&response) {
                        write_all_stream(io, &cobs_encode(&bytes)).await;
                    }
                    send_pending_events(io, server).await;
                }
            }
            Either::Second(ev) => {
                let Ok(n) = ev else {
                    return;
                };
                if n == 0 {
                    return;
                }
                server.push_uart_data(0, &evbuf[..n]);
                send_pending_events(io, server).await;
            }
        }
    }
}

/// `PacketIo` for embassy-usb 0.6's CDC-ACM class: the packet shapes match
/// 1:1, so every HAL that hands the firmware a `CdcAcmClass` (STM32 OTG,
/// ESP32-S3 OTG, the future F746) is plug-in ready.
#[cfg(feature = "embassy-usb")]
mod embassy_cdc {
    use super::PacketIo;
    use embassy_usb::class::cdc_acm::CdcAcmClass;
    use embassy_usb::driver::{Driver, EndpointError};

    impl<'d, D: Driver<'d>> PacketIo for CdcAcmClass<'d, D> {
        type Error = EndpointError;

        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            CdcAcmClass::read_packet(self, buf).await
        }

        async fn write_packet(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            CdcAcmClass::write_packet(self, data).await
        }
    }
}

#[cfg(feature = "embassy-net")]
mod embassy_tcp {
    use super::StreamIo;
    use embassy_net::tcp::TcpSocket;

    /// `StreamIo` for embassy-net 0.9's socket: `read` is inherent, the
    /// write side comes through its `embedded_io_async::Write` impl
    /// (version-matched to embassy-net's own requirement — see
    /// Cargo.toml).
    impl<'d> StreamIo for TcpSocket<'d> {
        type Error = embassy_net::tcp::Error;

        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            TcpSocket::read(self, buf).await
        }

        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            embedded_io_async::Write::write(self, buf).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use conwrt_agent_proto::dispatch::WireEndpoint;
    use conwrt_agent_proto::protocol::{CapabilityInfo, HandshakeRequest, PROTOCOL_VERSION};

    /// In-memory controller: feeds scripted COBS packets, records the
    /// agent's packetized writes (asserting packet-size discipline).
    struct MockPipe {
        requests: Vec<Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }

    impl PacketIo for MockPipe {
        type Error = &'static str;

        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            match self.requests.pop() {
                Some(packet) => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                None => Err("disconnected"),
            }
        }

        async fn write_packet(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            assert!(
                data.len() <= CDC_FS_PACKET,
                "write exceeds one packet: {} bytes",
                data.len()
            );
            self.writes.push(data.to_vec());
            Ok(())
        }
    }

    fn cobs_packets(frames: &[WireEndpoint]) -> Vec<Vec<u8>> {
        let mut wire = Vec::new();
        for (id, endpoint) in frames.iter().enumerate() {
            let frame = conwrt_agent_proto::dispatch::WireFrame::Request {
                id: id as u32,
                endpoint: endpoint.clone(),
            };
            let bytes = encode_frame(&frame).unwrap();
            wire.extend(cobs_encode(&bytes));
        }
        wire.chunks(CDC_FS_PACKET).map(<[u8]>::to_vec).collect()
    }

    fn server() -> ServerCore {
        ServerCore::new(
            "agent-io-test 0.1.0",
            Vec::from([CapabilityInfo {
                name: String::from("diag"),
                detail: Vec::from([
                    (String::from("chip"), String::from("test-chip")),
                    (String::from("fw"), String::from("agent-io-test 0.1.0")),
                    (String::from("heap_bytes"), String::from("49152")),
                ]),
            }]),
        )
    }

    async fn run_session(frames: &[WireEndpoint]) -> Vec<Vec<u8>> {
        let mut pipe = MockPipe {
            requests: cobs_packets(frames).into_iter().rev().collect(),
            writes: Vec::new(),
        };
        let mut core = server();
        agent_session(&mut pipe, &mut core, CDC_FS_PACKET).await;
        pipe.writes
    }

    fn decode_replies(writes: &[Vec<u8>]) -> Vec<conwrt_agent_proto::dispatch::WireFrame> {
        let mut pump = CobsPump::new();
        for packet in writes {
            pump.feed(packet);
        }
        let mut frames = Vec::new();
        while let Some(bytes) = pump.pop_frame() {
            frames.push(decode_frame(&bytes).unwrap());
        }
        frames
    }

    #[tokio::test]
    async fn handshake_and_capabilities_round_trip_through_the_session_loop() {
        let writes = run_session(&[
            WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION,
                controller_id: String::from("laptop"),
            }),
            WireEndpoint::Capabilities,
        ])
        .await;

        let frames = decode_replies(&writes);
        assert_eq!(frames.len(), 2, "handshake + capabilities replies");
        assert!(matches!(
            frames[0],
            conwrt_agent_proto::dispatch::WireFrame::Response {
                result: conwrt_agent_proto::dispatch::WireResult::Handshake(Ok(_)),
                ..
            }
        ));
        let conwrt_agent_proto::dispatch::WireFrame::Response {
            result: conwrt_agent_proto::dispatch::WireResult::Capabilities(caps),
            ..
        } = &frames[1]
        else {
            panic!("expected capabilities reply");
        };
        assert_eq!(caps[0].name, "diag");
        assert_eq!(caps[0].detail[0].0, "chip");
    }

    #[tokio::test]
    async fn multiple_frames_in_one_packet_are_all_served() {
        // Two COBS frames coalesced into one sub-64-byte read, as USB
        // delivers them when the controller writes back-to-back.
        let mut wire = Vec::new();
        for (id, endpoint) in [
            WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION,
                controller_id: String::from("laptop"),
            }),
            WireEndpoint::Capabilities,
        ]
        .into_iter()
        .enumerate()
        {
            let frame = conwrt_agent_proto::dispatch::WireFrame::Request {
                id: id as u32,
                endpoint,
            };
            wire.extend(cobs_encode(&encode_frame(&frame).unwrap()));
        }
        assert!(wire.len() < CDC_FS_PACKET, "fixture must coalesce");
        let mut pipe = MockPipe {
            requests: vec![wire],
            writes: Vec::new(),
        };
        let mut core = server();
        agent_session(&mut pipe, &mut core, CDC_FS_PACKET).await;
        assert_eq!(decode_replies(&pipe.writes).len(), 2);
    }

    #[tokio::test]
    async fn exact_packet_boundary_write_appends_zero_length_packet() {
        let mut pipe = MockPipe {
            requests: Vec::new(),
            writes: Vec::new(),
        };
        write_packetized(&mut pipe, &[0xAB; CDC_FS_PACKET], CDC_FS_PACKET).await;
        assert_eq!(pipe.writes.len(), 2, "payload packet + ZLP");
        assert_eq!(pipe.writes[0].len(), CDC_FS_PACKET);
        assert!(pipe.writes[1].is_empty());
    }

    #[tokio::test]
    async fn garbage_bytes_do_not_kill_the_session() {
        // COBS pump discards undecodable frames; the session keeps serving
        // the valid frame that follows.
        let mut wire = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let frame = conwrt_agent_proto::dispatch::WireFrame::Request {
            id: 9,
            endpoint: WireEndpoint::Capabilities,
        };
        wire.extend(cobs_encode(&encode_frame(&frame).unwrap()));
        let mut pipe = MockPipe {
            requests: vec![wire],
            writes: Vec::new(),
        };
        let mut core = server();
        agent_session(&mut pipe, &mut core, CDC_FS_PACKET).await;
        assert_eq!(decode_replies(&pipe.writes).len(), 1);
    }
}
