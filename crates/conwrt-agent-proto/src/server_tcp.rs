//! HIL mock server: the MCU agent's exact brain ([`crate::server::ServerCore`])
//! behind the std TCP wire (#110). The controller side cannot tell it apart
//! from the firmware — same codec, same frames, same session semantics — so
//! host-side tests exercise the full controller→MCU-agent path without
//! hardware. The firmware's USB CDC transport plugs into the same
//! [`ServerCore`]; only the byte pipe differs.
//!
//! # Talking to the real firmware from this host
//!
//! `AgentClient` speaks TCP; the firmware speaks USB CDC-ACM. A socat
//! bridge swaps the byte pipe with zero code:
//!
//! ```text
//! socat TCP-LISTEN:8400,reuseaddr,fork FILE:/dev/ttyACM0,b115200,raw,echo=0
//! ```
//!
//! …then every TCP client (these tests, the CLI) addresses the board
//! unchanged. That is the on-device bring-up recipe for #110's bench stage;
//! the ESP32-S3 agent (#111) enumerates as a CDC-ACM `ttyACM` device too —
//! same recipe, same frames (`s3_diag_mock` is its scripted peer).

use alloc::string::String;
use alloc::vec::Vec;
use std::io;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::dispatch::{WireError, WireFrame, decode_frame, encode_frame};
use crate::protocol::CapabilityInfo;
use crate::server::{ServerCore, UartSink};
use crate::wire::{CobsReceiver, CobsSender};

/// Accept loop: one controller at a time, a fresh [`ServerCore`] session per
/// connection (mirrors the firmware's connection-lifecycle semantics).
pub async fn run_mock_on(listener: TcpListener, server: &mut ServerCore) {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if let Err(e) = mock_connection(socket, server).await {
            eprintln!("[hil-mock] connection ended: {e}");
        }
    }
}

async fn mock_connection(socket: TcpStream, server: &mut ServerCore) -> io::Result<()> {
    let (mut rx, tx) = socket.into_split();
    let mut sender = CobsSender::new(tx);
    let mut receiver = CobsReceiver::new();
    server.reset_session();
    while let Some(frame_bytes) = receiver.receive(&mut rx).await? {
        let Some(response) = decode_frame(&frame_bytes)
            .ok()
            .and_then(|frame| server.handle_frame(frame))
        else {
            continue;
        };
        sender.send(&frame_bytes_of(&response)?).await?;
        send_events(&mut sender, server).await?;
    }
    Ok(())
}

fn frame_bytes_of(frame: &WireFrame) -> io::Result<Vec<u8>> {
    encode_frame(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Convenience: mock advertising a `serial` capability with `uarts` count.
#[must_use]
pub fn serial_mock(agent_version: &str, uarts: u32) -> ServerCore {
    ServerCore::new(agent_version, serial_caps(uarts))
}

fn serial_caps(uarts: u32) -> Vec<CapabilityInfo> {
    vec![CapabilityInfo {
        name: String::from("serial"),
        detail: vec![(String::from("uarts"), uarts.to_string())],
    }]
}

/// Convenience mock mirroring the ESP32-S3 firmware's `diag` capability
/// (#111): chip identity, firmware version, and heap size in the
/// advertisement — the mock-first stage of that issue's acceptance
/// ("mock-first; bench when authorized"). Serve it with [`run_mock_on`];
/// the firmware (`apps/conwrt-esp32s3`) drives the same [`ServerCore`]
/// over USB-CDC with the identical advertisement.
#[must_use]
pub fn s3_diag_mock(agent_version: &str, heap_bytes: usize) -> ServerCore {
    ServerCore::new(
        agent_version,
        vec![CapabilityInfo {
            name: String::from("diag"),
            detail: vec![
                (String::from("chip"), String::from("esp32s3")),
                (String::from("fw"), agent_version.to_string()),
                (String::from("heap_bytes"), heap_bytes.to_string()),
            ],
        }],
    )
}

/// The scripted peer of #110's acceptance criterion: every byte the
/// controller writes to the UART comes back as an `AgentEvent::UartData` —
/// the full controller → agent → UART sink → RX event → controller loop,
/// exercised on host with zero hardware.
///
/// Per connection this builds a fresh [`ServerCore`] whose [`UartSink`]
/// echoes through an mpsc channel; a `select!` loop serves controller
/// frames and echo arrivals concurrently (TCP receives are
/// cancellation-safe: unread bytes stay kernel-buffered).
pub async fn run_echo_mock_on(listener: TcpListener, agent_version: &'static str) {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if let Err(e) = echo_connection(socket, agent_version).await {
            eprintln!("[echo-mock] connection ended: {e}");
        }
    }
}

struct EchoSink {
    echo_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl UartSink for EchoSink {
    fn uart_write(&mut self, _port: u8, data: &[u8]) -> Result<usize, WireError> {
        let _ = self.echo_tx.send(data.to_vec());
        Ok(data.len())
    }
}

async fn echo_connection(socket: TcpStream, agent_version: &str) -> io::Result<()> {
    let (mut rx, tx) = socket.into_split();
    let mut sender = CobsSender::new(tx);
    let mut receiver = CobsReceiver::new();
    let (echo_tx, mut echo_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut server = ServerCore::with_uart(
        agent_version,
        serial_caps(1),
        Box::new(EchoSink { echo_tx }),
    )
    // #215 slice 5: the echo path doubles as the detect HIL vehicle —
    // controller DetectStart arms the tracker, echoed writes feed it
    // RX bytes, latched milestones flow back as DetectFinding events.
    // Unarmed until DetectStart, so existing echo behavior is
    // unchanged.
    .attach_detect(0);
    server.reset_session();
    // Lease clock (#380): heartbeat expiry must be exercisable over
    // this transport too — one tick per heartbeat interval.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(1000));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                for event in server.tick() {
                    sender.send(&frame_bytes_of(&WireFrame::Event(event))?).await?;
                }
            }
            frame_bytes = receiver.receive(&mut rx) => {
                let Some(frame_bytes) = frame_bytes? else {
                    return Ok(());
                };
                let Some(response) = decode_frame(&frame_bytes)
                    .ok()
                    .and_then(|frame| server.handle_frame(frame))
                else {
                    continue;
                };
                sender.send(&frame_bytes_of(&response)?).await?;
                send_events(&mut sender, &mut server).await?;
            }
            echoed = echo_rx.recv() => {
                let Some(bytes) = echoed else {
                    return Ok(());
                };
                server.push_uart_data(0, &bytes);
                send_events(&mut sender, &mut server).await?;
            }
        }
    }
}

async fn send_events(sender: &mut CobsSender, server: &mut ServerCore) -> io::Result<()> {
    for event in server.take_events() {
        sender
            .send(&frame_bytes_of(&WireFrame::Event(event))?)
            .await?;
    }
    Ok(())
}
