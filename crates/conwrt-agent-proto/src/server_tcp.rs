//! HIL mock server: the MCU agent's exact brain ([`crate::server::ServerCore`])
//! behind the std TCP wire (#110). The controller side cannot tell it apart
//! from the firmware — same codec, same frames, same session semantics — so
//! host-side tests exercise the full controller→MCU-agent path without
//! hardware. The firmware's USB CDC transport plugs into the same
//! [`ServerCore`]; only the byte pipe differs.

use alloc::string::String;
use std::io;

use tokio::net::{TcpListener, TcpStream};

use crate::dispatch::{WireFrame, decode_frame, encode_frame};
use crate::server::ServerCore;
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
        for event in server.take_events() {
            sender
                .send(&frame_bytes_of(&WireFrame::Event(event))?)
                .await?;
        }
    }
    Ok(())
}

fn frame_bytes_of(frame: &WireFrame) -> io::Result<Vec<u8>> {
    encode_frame(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Convenience: mock advertising a `serial` capability with `uarts` count.
#[must_use]
pub fn serial_mock(agent_version: &str, uarts: u32) -> ServerCore {
    ServerCore::new(
        agent_version,
        alloc::vec![crate::protocol::CapabilityInfo {
            name: String::from("serial"),
            detail: alloc::vec![(String::from("uarts"), uarts.to_string())],
        }],
    )
}
