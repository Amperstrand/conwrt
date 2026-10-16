//! Event-pumping session semantics (#215 slice 4 prep): the firmware
//! shape — a stream session selected against a live [`EventSource`], both
//! driving one `ServerCore`. The contract under test: UART data flows to
//! the controller as it arrives, with no request needed to flush it.

use conwrt_agent_io::{EventSource, StreamIo, agent_session_stream_events};
use conwrt_agent_proto::cobs::{CobsPump, encode_frame as cobs_encode};
use conwrt_agent_proto::dispatch::{
    AgentEvent, WireEndpoint, WireFrame, decode_frame, encode_frame,
};
use conwrt_agent_proto::protocol::{HandshakeRequest, PROTOCOL_VERSION};
use conwrt_agent_proto::server::ServerCore;
use tokio::sync::mpsc;

/// Stream whose reads pend on a channel (cancel-safe), writes recorded.
struct ChanStream {
    reads: mpsc::Receiver<Vec<u8>>,
    written: Vec<u8>,
}

impl StreamIo for ChanStream {
    type Error = &'static str;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.reads.recv().await {
            Some(chunk) => {
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            None => Ok(0),
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        self.written.extend_from_slice(data);
        Ok(data.len())
    }
}

/// Event source fed by a channel; a dropped sender is `Ok(0)` (closed).
struct ChanEvents {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl EventSource for ChanEvents {
    type Error = &'static str;

    async fn wait_data(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.rx.recv().await {
            Some(chunk) => {
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            None => Ok(0),
        }
    }
}

fn server() -> ServerCore {
    ServerCore::new("agent-io-events-test 0.1.0", Vec::new())
}

fn handshake_request() -> Vec<u8> {
    let frame = WireFrame::Request {
        id: 0,
        endpoint: WireEndpoint::Handshake(HandshakeRequest {
            protocol_version: PROTOCOL_VERSION,
            controller_id: String::from("laptop"),
        }),
    };
    cobs_encode(&encode_frame(&frame).unwrap())
}

fn decode_frames(raw: &[u8]) -> Vec<WireFrame> {
    let mut pump = CobsPump::new();
    pump.feed(raw);
    let mut frames = Vec::new();
    while let Some(bytes) = pump.pop_frame() {
        frames.push(decode_frame(&bytes).unwrap());
    }
    frames
}

#[tokio::test]
async fn uart_event_flows_without_any_request() {
    let (stx, srx) = mpsc::channel(4);
    let (etx, erx) = mpsc::channel(4);
    etx.send(b"boot banner".to_vec()).await.unwrap();
    drop(etx);
    let session = tokio::spawn(async move {
        let mut io = ChanStream {
            reads: srx,
            written: Vec::new(),
        };
        let mut ev = ChanEvents { rx: erx };
        let mut core = server();
        agent_session_stream_events(&mut io, &mut ev, &mut core).await;
        io.written
    });
    // Let the live session serve the queued event, then close the stream
    // to end it deterministically.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(stx);
    let written = session.await.unwrap();
    let frames = decode_frames(&written);
    assert_eq!(frames.len(), 1, "one unsolicited event, zero responses");
    assert!(matches!(
        &frames[0],
        WireFrame::Event(AgentEvent::UartData { port: 0, data }) if data == b"boot banner"
    ));
}

#[tokio::test]
async fn request_reply_and_event_interleave() {
    let (stx, srx) = mpsc::channel(4);
    let (etx, erx) = mpsc::channel(4);
    etx.send(b"kernel: link up".to_vec()).await.unwrap();
    stx.send(handshake_request()).await.unwrap();
    let session = tokio::spawn(async move {
        let mut io = ChanStream {
            reads: srx,
            written: Vec::new(),
        };
        let mut ev = ChanEvents { rx: erx };
        let mut core = server();
        agent_session_stream_events(&mut io, &mut ev, &mut core).await;
        io.written
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(stx);
    drop(etx);
    let written = session.await.unwrap();
    let frames = decode_frames(&written);
    assert_eq!(frames.len(), 2, "handshake response + uart event");
    let responses = frames
        .iter()
        .filter(|f| matches!(f, WireFrame::Response { .. }))
        .count();
    let events = frames
        .iter()
        .filter(|f| {
            matches!(
                f,
                WireFrame::Event(AgentEvent::UartData { port: 0, data }) if data == b"kernel: link up"
            )
        })
        .count();
    assert_eq!(
        (responses, events),
        (1, 1),
        "one of each, order not asserted"
    );
}

#[tokio::test]
async fn event_source_close_ends_session_without_killing_pending_stream() {
    let (stx, srx) = mpsc::channel(4);
    let (etx, erx) = mpsc::channel(4);
    drop(etx); // source closed
    stx.send(handshake_request()).await.unwrap();
    let mut io = ChanStream {
        reads: srx,
        written: Vec::new(),
    };
    let mut ev = ChanEvents { rx: erx };
    let mut core = server();
    agent_session_stream_events(&mut io, &mut ev, &mut core).await;
    // Whichever side the select resolves first, the session must end
    // (returning here proves it) having served at most the one request.
    assert!(decode_frames(&io.written).len() <= 1);
}
