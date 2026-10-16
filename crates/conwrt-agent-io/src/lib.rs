//! # conwrt-agent-io
//!
//! The transport-session layer shared by every MCU agent firmware
//! (#215 slice 1): [`ServerCore`] behind one packet-shaped byte pipe.
//!
//! Both existing firmware apps (#110 STM32-F469, #111 ESP32-S3) drove the
//! same copy-pasted loop — CDC read → [`CobsPump`] → [`ServerCore`] →
//! packetized write. That loop lives here once, generic over [`PacketIo`],
//! so a third app (STM32-F746, #215 slice 2) is board-init plus a trait
//! impl instead of another transport fork. The trait is deliberately NOT
//! `embedded-io-async`: packet-shaped reads/writes map 1:1 onto
//! embassy-usb 0.6's `CdcAcmClass` on every HAL we use, and owning the
//! trait avoids the embedded-io-async version-split trap in mixed
//! embassy-version dependency graphs.
//!
//! Host tests drive the exact session loop with an in-memory mock pipe and
//! a real `ServerCore` — the firmware transport path has persisted
//! regression coverage without hardware (ADR-0011 ring 1).

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

use conwrt_agent_proto::cobs::{CobsPump, encode_frame as cobs_encode};
use conwrt_agent_proto::dispatch::{decode_frame, encode_frame};
use conwrt_agent_proto::server::ServerCore;

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
