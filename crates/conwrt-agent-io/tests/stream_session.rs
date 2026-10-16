//! Stream-session semantics (#215 slice 3): the `MockStream` twin of the
//! packet `MockPipe` in `src/lib.rs` — the session loop is chunk-size
//! independent (TCP delivers arbitrary boundaries), tolerates partial
//! writes, ends cleanly on `Ok(0)` (peer close), and survives garbage.

use conwrt_agent_io::{StreamIo, agent_session_stream, write_all_stream};
use conwrt_agent_proto::cobs::{CobsPump, encode_frame as cobs_encode};
use conwrt_agent_proto::dispatch::{WireEndpoint, WireFrame, decode_frame, encode_frame};
use conwrt_agent_proto::protocol::{CapabilityInfo, HandshakeRequest, PROTOCOL_VERSION};
use conwrt_agent_proto::server::ServerCore;

/// In-memory stream: serves scripted read chunks in order (an empty chunk
/// is `Ok(0)` = peer close), records writes, and can cap each write call
/// to simulate partial writes.
struct MockStream {
    read_chunks: Vec<Vec<u8>>,
    written: Vec<u8>,
    write_cap: usize,
}

impl StreamIo for MockStream {
    type Error = &'static str;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.read_chunks.first() {
            Some(chunk) if chunk.len() <= buf.len() => {
                let n = chunk.len();
                buf[..n].copy_from_slice(chunk);
                self.read_chunks.remove(0);
                Ok(n)
            }
            Some(chunk) => {
                let n = buf.len();
                buf.copy_from_slice(&chunk[..n]);
                self.read_chunks[0] = chunk[n..].to_vec();
                Ok(n)
            }
            None => Err("disconnected"),
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        let n = if self.write_cap == 0 {
            data.len()
        } else {
            data.len().min(self.write_cap)
        };
        self.written.extend_from_slice(&data[..n]);
        Ok(n)
    }
}

/// Stream whose writes always report `Ok(0)` (stalled peer), counting
/// calls so a runaway write loop is detectable.
struct ZeroWriter {
    calls: usize,
}

impl StreamIo for ZeroWriter {
    type Error = &'static str;

    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Err("unused")
    }

    async fn write(&mut self, _data: &[u8]) -> Result<usize, Self::Error> {
        self.calls += 1;
        Ok(0)
    }
}

fn server() -> ServerCore {
    ServerCore::new(
        "agent-io-stream-test 0.1.0",
        Vec::from([CapabilityInfo {
            name: String::from("diag"),
            detail: Vec::from([(String::from("chip"), String::from("test-chip"))]),
        }]),
    )
}

fn request_bytes(id: u32, endpoint: WireEndpoint) -> Vec<u8> {
    let frame = WireFrame::Request { id, endpoint };
    cobs_encode(&encode_frame(&frame).unwrap())
}

fn handshake_and_caps_wire() -> Vec<u8> {
    let mut wire = request_bytes(
        0,
        WireEndpoint::Handshake(HandshakeRequest {
            protocol_version: PROTOCOL_VERSION,
            controller_id: String::from("laptop"),
        }),
    );
    wire.extend(request_bytes(1, WireEndpoint::Capabilities));
    wire
}

fn decode_replies(raw: &[u8]) -> Vec<WireFrame> {
    let mut pump = CobsPump::new();
    pump.feed(raw);
    let mut frames = Vec::new();
    while let Some(bytes) = pump.pop_frame() {
        frames.push(decode_frame(&bytes).unwrap());
    }
    frames
}

async fn run(read_chunks: Vec<Vec<u8>>, write_cap: usize) -> MockStream {
    let mut io = MockStream {
        read_chunks,
        written: Vec::new(),
        write_cap,
    };
    let mut core = server();
    agent_session_stream(&mut io, &mut core).await;
    io
}

#[tokio::test]
async fn odd_chunk_boundaries_do_not_split_or_lose_frames() {
    // TCP hands the loop arbitrary boundaries: split the wire at odd
    // offsets so COBS delimiters land mid-chunk and single bytes arrive
    // alone.
    let wire = handshake_and_caps_wire();
    let chunks: Vec<Vec<u8>> = wire
        .chunks(3)
        .enumerate()
        .flat_map(|(i, c)| {
            let v = c.to_vec();
            if i % 2 == 0 {
                vec![v]
            } else {
                v.into_iter().map(|b| vec![b]).collect()
            }
        })
        .collect();
    let io = run(chunks, 0).await;
    let frames = decode_replies(&io.written);
    assert_eq!(frames.len(), 2, "handshake + capabilities replies");
}

#[tokio::test]
async fn zero_length_read_ends_the_session_without_serving_later_chunks() {
    let later = request_bytes(7, WireEndpoint::Capabilities);
    let io = run(vec![handshake_and_caps_wire(), Vec::new(), later], 0).await;
    let frames = decode_replies(&io.written);
    assert_eq!(frames.len(), 2, "chunk after peer-close stays unserved");
}

#[tokio::test]
async fn partial_writes_still_emit_complete_frames() {
    let io = run(vec![handshake_and_caps_wire()], 1).await;
    let frames = decode_replies(&io.written);
    assert_eq!(
        frames.len(),
        2,
        "one-byte-per-write still delivers both replies"
    );
}

#[tokio::test]
async fn garbage_bytes_do_not_kill_the_stream_session() {
    let mut wire = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    wire.extend(request_bytes(9, WireEndpoint::Capabilities));
    let io = run(vec![wire], 0).await;
    assert_eq!(decode_replies(&io.written).len(), 1);
}

#[tokio::test]
async fn queued_event_follows_the_reply_that_drained_it() {
    // Events queued before the session (e.g. a boot banner pushed by the
    // UART task) must follow the first response out — the std pump's
    // send_events ordering.
    let mut core = server();
    core.push_uart_data(0, b"boot banner");
    let mut io = MockStream {
        read_chunks: vec![request_bytes(0, WireEndpoint::Capabilities)],
        written: Vec::new(),
        write_cap: 0,
    };
    agent_session_stream(&mut io, &mut core).await;
    let frames = decode_replies(&io.written);
    assert_eq!(frames.len(), 2, "capabilities response + uart event");
    assert!(matches!(
        frames[1],
        WireFrame::Event(conwrt_agent_proto::dispatch::AgentEvent::UartData { port: 0, .. })
    ));
}

#[tokio::test]
async fn write_all_stream_returns_on_zero_byte_write() {
    let mut stalled = ZeroWriter { calls: 0 };
    write_all_stream(&mut stalled, b"any").await;
    assert_eq!(stalled.calls, 1, "stalled peer ends the write loop");
}
