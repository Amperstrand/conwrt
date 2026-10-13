//! # postcard-rpc spike (#107, ADR-0004) — phase 2
//!
//! Phase 1 (proven): TCP transport via custom COBS wire, both sides,
//! 1000 echo round-trips @ 46µs/rtt, 236 LOC wire glue.
//!
//! Phase 2 (this file adds): firmware-sized streaming with backpressure
//! and resume — the remaining ADR-0004 kill-criteria measurement:
//! - `/chunk`:  lock-step chunk push (await per-chunk ack => backpressure
//!   by construction; no unbounded buffering anywhere)
//! - `/status`: device-reported contiguous offset per transfer id
//! - the host KILLS the connection mid-transfer, reconnects, queries
//!   status, resumes, and the assembled payload's sha256 must match
//!
//! Device transfer state lives in Arc<Mutex<HashMap>> shared across
//! per-connection dispatchers, so resume survives reconnects exactly as
//! an agent's would across controller loss.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use postcard_rpc::accumulator::raw::{CobsAccumulator, FeedResult};
use postcard_rpc::header::{VarHeader, VarKey, VarKeyKind, VarSeq, VarSeqKind};
use postcard_rpc::host_client::HostClient;
use postcard_rpc::server::Server;
use postcard_rpc::{define_dispatch, endpoints, topics, TopicDirection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Protocol definition
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Serialize, Deserialize, postcard_schema::Schema)]
pub enum WireErr {
    UnknownEndpoint,
    BadRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, postcard_schema::Schema)]
pub struct FirmwareChunk {
    pub id: u32,
    pub offset: u32,
    pub total: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, postcard_schema::Schema)]
pub struct ChunkAck {
    pub offset: u32,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, postcard_schema::Schema)]
pub struct TransferStatus {
    pub offset: u32,
    pub total: u32,
    pub done: bool,
}

endpoints! {
    list = ENDPOINT_LIST;
    | EndpointTy   | RequestTy     | ResponseTy     | Path      |
    | ------------ | ------------- | -------------- | --------- |
    | EchoEndpoint | String        | String         | "/echo"   |
    | ChunkEndpoint | FirmwareChunk | ChunkAck      | "/chunk"  |
    | StatusEndpoint | u32          | TransferStatus | "/status" |
}

topics! {
    list = TOPICS_IN_LIST;
    direction = TopicDirection::ToServer;
    | TopicTy | MessageTy | Path |
    | ------- | --------- | ---- |
}

topics! {
    list = TOPICS_OUT_LIST;
    direction = TopicDirection::ToClient;
    | TopicTy | MessageTy | Path |
    | ------- | --------- | ---- |
}

// ---------------------------------------------------------------------------
// Host-side TCP wire (identical to phase 1, buffer sized for 4 KiB chunks)
// ---------------------------------------------------------------------------

mod host_wire {
    use super::*;
    use postcard_rpc::host_client::{WireRx, WireSpawn, WireTx};

    pub struct TokioSpawn;
    impl WireSpawn for TokioSpawn {
        fn spawn(&mut self, fut: impl Future<Output = ()> + Send + 'static) {
            core::mem::drop(tokio::task::spawn(fut));
        }
    }

    pub struct TcpWireTx {
        pub tx: tokio::io::WriteHalf<tokio::net::TcpStream>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("tcp tx: {0}")]
    pub struct TxError(#[from] std::io::Error);

    impl WireTx for TcpWireTx {
        type Error = TxError;
        async fn send(&mut self, data: Vec<u8>) -> Result<(), TxError> {
            use tokio::io::AsyncWriteExt;
            let mut msg = cobs::encode_vec(&data);
            msg.push(0);
            self.tx.write_all(&msg).await?;
            Ok(())
        }
    }

    pub struct TcpWireRx {
        pub rx: tokio::io::ReadHalf<tokio::net::TcpStream>,
        pub buf: Box<[u8; 8192]>,
        pub acc: Box<CobsAccumulator<8192>>,
        pub pending: VecDeque<Vec<u8>>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("tcp rx: {0}")]
    pub struct RxError(#[from] std::io::Error);

    impl WireRx for TcpWireRx {
        type Error = RxError;
        async fn receive(&mut self) -> Result<Vec<u8>, RxError> {
            use tokio::io::AsyncReadExt;
            loop {
                if let Some(p) = self.pending.pop_front() {
                    return Ok(p);
                }
                let n = self.rx.read(&mut self.buf[..]).await?;
                if n == 0 {
                    return Err(RxError(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    )));
                }
                let mut window = &self.buf[..n];
                while !window.is_empty() {
                    window = match self.acc.feed(window) {
                        FeedResult::Consumed => break,
                        FeedResult::OverFull(w) => w,
                        FeedResult::DeserError(w) => w,
                        FeedResult::Success { data, remaining } => {
                            self.pending.push_back(data.to_vec());
                            remaining
                        }
                    };
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Device-side TCP wire (identical to phase 1, buffer sized for 4 KiB chunks)
// ---------------------------------------------------------------------------

mod device_wire {
    use super::*;
    use postcard_rpc::server::{
        AsWireRxErrorKind, AsWireTxErrorKind, WireRx, WireRxErrorKind, WireTx, WireTxErrorKind,
    };

    #[derive(Debug, thiserror::Error)]
    pub enum WireError {
        #[error("io: {0}")]
        Io(#[from] std::io::Error),
        #[error("serialize: {0}")]
        Serde(#[from] postcard::Error),
    }

    impl AsWireTxErrorKind for WireError {
        fn as_kind(&self) -> WireTxErrorKind {
            match self {
                WireError::Io(_) => WireTxErrorKind::ConnectionClosed,
                WireError::Serde(_) => WireTxErrorKind::Other,
            }
        }
    }

    impl AsWireRxErrorKind for WireError {
        fn as_kind(&self) -> WireRxErrorKind {
            match self {
                WireError::Io(_) => WireRxErrorKind::ConnectionClosed,
                WireError::Serde(_) => WireRxErrorKind::Other,
            }
        }
    }

    pub struct ServerTcpTx {
        pub tx: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
        pub log_ctr: std::sync::atomic::AtomicU32,
    }

    impl Clone for ServerTcpTx {
        fn clone(&self) -> Self {
            Self {
                tx: Arc::clone(&self.tx),
                log_ctr: std::sync::atomic::AtomicU32::new(
                    self.log_ctr.load(std::sync::atomic::Ordering::Relaxed),
                ),
            }
        }
    }

    impl WireTx for ServerTcpTx {
        type Error = WireError;

        async fn send<T: Serialize + ?Sized>(&self, hdr: VarHeader, msg: &T) -> Result<(), WireError> {
            let mut frame = hdr.write_to_vec();
            let body = postcard::to_stdvec(msg)?;
            frame.extend_from_slice(&body);
            self.send_raw(&frame).await
        }

        async fn send_raw(&self, buf: &[u8]) -> Result<(), WireError> {
            use tokio::io::AsyncWriteExt;
            let mut msg = cobs::encode_vec(buf);
            msg.push(0);
            let mut tx = self.tx.lock().await;
            tx.write_all(&msg).await?;
            Ok(())
        }

        async fn send_log_str(&self, kkind: VarKeyKind, s: &str) -> Result<(), WireError> {
            let wh = VarHeader {
                key: VarKey::Key8(postcard_rpc::standard_icd::LoggingTopic::TOPIC_KEY),
                seq_no: VarSeq::Seq4(
                    self.log_ctr
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ),
            };
            self.send(wh, &s).await?;
            let _ = kkind;
            Ok(())
        }

        async fn send_log_fmt<'a>(
            &self,
            kkind: VarKeyKind,
            args: std::fmt::Arguments<'a>,
        ) -> Result<(), WireError> {
            self.send_log_str(kkind, &args.to_string()).await
        }
    }

    pub struct ServerTcpRx {
        pub rx: tokio::io::ReadHalf<tokio::net::TcpStream>,
        pub buf: Box<[u8; 8192]>,
        pub acc: Box<CobsAccumulator<8192>>,
        pub pending: VecDeque<Vec<u8>>,
    }

    impl WireRx for ServerTcpRx {
        type Error = WireError;

        async fn receive<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], WireError> {
            use tokio::io::AsyncReadExt;
            loop {
                if let Some(frame) = self.pending.pop_front() {
                    if frame.len() > buf.len() {
                        return Err(WireError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "frame larger than server buffer",
                        )));
                    }
                    buf[..frame.len()].copy_from_slice(&frame);
                    return Ok(&mut buf[..frame.len()]);
                }
                let n = self.rx.read(&mut self.buf[..]).await?;
                if n == 0 {
                    return Err(WireError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    )));
                }
                let mut window = &self.buf[..n];
                while !window.is_empty() {
                    window = match self.acc.feed(window) {
                        FeedResult::Consumed => break,
                        FeedResult::OverFull(w) => w,
                        FeedResult::DeserError(w) => w,
                        FeedResult::Success { data, remaining } => {
                            self.pending.push_back(data.to_vec());
                            remaining
                        }
                    };
                }
            }
        }
    }

    pub mod dispatch_impl {
        use std::future::Future;

        pub type WireTxImpl = super::ServerTcpTx;

        pub fn spawn_fn<Sp, F>(_sp: &Sp, fut: F) -> Result<(), Sp::Error>
        where
            Sp: postcard_rpc::server::WireSpawn<Error = std::convert::Infallible, Info = ()>,
            F: Future<Output = ()> + Send + 'static,
        {
            core::mem::drop(tokio::task::spawn(fut));
            Ok(())
        }
    }

    /// Server-side spawn context (tokio).
    #[derive(Clone)]
    pub struct ServerSpawn;
}

use device_wire::dispatch_impl::spawn_fn;
use device_wire::ServerSpawn;
use postcard_rpc::Topic;

// ---------------------------------------------------------------------------
// Device application: echo + firmware-chunk assembly with durable transfers
// ---------------------------------------------------------------------------

/// Transfer store shared across connection lifetimes (resume support).
pub type Transfers = Arc<std::sync::Mutex<HashMap<u32, (Vec<u8>, u32)>>>;

pub struct Ctx {
    pub transfers: Transfers,
}

async fn echo_handler(_ctx: &mut Ctx, _hdr: VarHeader, req: String) -> String {
    req
}

async fn chunk_handler(
    ctx: &mut Ctx,
    _hdr: VarHeader,
    chunk: FirmwareChunk,
) -> ChunkAck {
    // Simulated flash write: accept ONLY the next contiguous chunk.
    let mut transfers = ctx.transfers.lock().unwrap();
    let entry = transfers.entry(chunk.id).or_insert_with(|| (Vec::new(), chunk.total));
    let (data, total) = entry;
    *total = chunk.total;
    if chunk.offset as usize == data.len() {
        data.extend_from_slice(&chunk.data);
    }
    // Out-of-order/duplicate chunks are dropped silently (idempotent resume).
    let done = data.len() == *total as usize;
    ChunkAck { offset: data.len() as u32, done }
}

async fn status_handler(_ctx: &mut Ctx, _hdr: VarHeader, id: u32) -> TransferStatus {
    let transfers = _ctx.transfers.lock().unwrap();
    match transfers.get(&id) {
        Some((data, total)) => TransferStatus {
            offset: data.len() as u32,
            total: *total,
            done: data.len() == *total as usize,
        },
        None => TransferStatus { offset: 0, total: 0, done: false },
    }
}

define_dispatch! {
    app: SingleDispatcher;
    spawn_fn: spawn_fn;
    tx_impl: device_wire::dispatch_impl::WireTxImpl;
    spawn_impl: ServerSpawn;
    context: Ctx;

    endpoints: {
        list: ENDPOINT_LIST;

        | EndpointTy    | kind  | handler        |
        | ------------- | ----- | -------------- |
        | EchoEndpoint  | async | echo_handler   |
        | ChunkEndpoint | async | chunk_handler  |
        | StatusEndpoint | async | status_handler |
    };
    topics_in: {
        list: TOPICS_IN_LIST;

        | TopicTy | kind | handler |
        | ------- | ---- | ------- |
    };
    topics_out: {
        list: TOPICS_OUT_LIST;
    };
}

// ---------------------------------------------------------------------------
// Main: device (listener loop) + host (connect, stream, kill, resume, verify)
// ---------------------------------------------------------------------------

async fn client_at(addr: std::net::SocketAddr) -> HostClient<WireErr> {
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (rx, tx) = tokio::io::split(socket);
    HostClient::new_with_wire(
        host_wire::TcpWireTx { tx },
        host_wire::TcpWireRx {
            rx,
            buf: Box::new([0u8; 8192]),
            acc: Box::new(CobsAccumulator::new()),
            pending: VecDeque::new(),
        },
        host_wire::TokioSpawn,
        VarSeqKind::Seq1,
        "err",
        8,
    )
}

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Shared transfer store: survives per-connection dispatchers.
    let transfers: Transfers = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Device side: accept loop — a dead connection ends server.run(), we
    // rebuild the server (same shared store) for the next controller.
    let device_transfers = Arc::clone(&transfers);
    let device = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            eprintln!("[device] connection accepted");
            let (rx, tx) = tokio::io::split(socket);
            let stx = device_wire::ServerTcpTx {
                tx: Arc::new(tokio::sync::Mutex::new(tx)),
                log_ctr: std::sync::atomic::AtomicU32::new(0),
            };
            let srx = device_wire::ServerTcpRx {
                rx,
                buf: Box::new([0u8; 8192]),
                acc: Box::new(CobsAccumulator::new()),
                pending: VecDeque::new(),
            };
            let dispatch = SingleDispatcher::new(
                Ctx { transfers: Arc::clone(&device_transfers) },
                device_wire::ServerSpawn,
            );
            let mut server: Server<_, _, Box<[u8]>, _> =
                Server::new(stx, srx, vec![0u8; 16384].into(), dispatch, VarKeyKind::Key8);
            let _ = server.run().await;
            eprintln!("[device] server.run() RETURNED (connection over)");
        }
    });

    // ---- Phase 1 regression: echo ----
    let client = client_at(addr).await;
    let resp = client
        .send_resp::<EchoEndpoint>(&"hello".to_string())
        .await
        .expect("echo");
    assert_eq!(resp, "hello");
    println!("echo: ok");

    // ---- Phase 2: firmware-sized streaming with kill + resume ----
    let quick = std::env::var("QUICK").is_ok();
    let chunk_size: usize = if quick { 256 } else { 4096 };
    let total_size: usize = if quick { 1024 } else { 5 * 1024 * 1024 };
    let CHUNK: usize = chunk_size;
    let TOTAL: usize = total_size;
    let transfer_id: u32 = 7;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let expect_sha = Sha256::digest(&payload);
    println!("payload: {TOTAL} bytes in {CHUNK}-byte chunks");

    let t0 = Instant::now();
    drop(client); // release the echo connection so the device can accept the streaming one
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let client = client_at(addr).await;

    // Send the first 40% lock-step (backpressure by construction: each
    // chunk's ack is awaited before the next is written).
    let kill_after = (TOTAL / CHUNK) * 40 / 100;
    for i in 0..kill_after {
        let offset = i * CHUNK;
        let ack = client
            .send_resp::<ChunkEndpoint>(&FirmwareChunk {
                id: transfer_id,
                offset: offset as u32,
                total: TOTAL as u32,
                data: payload[offset..offset + CHUNK].to_vec(),
            })
            .await
            .expect("chunk ack");
        assert_eq!(ack.offset as usize, offset + CHUNK);
    }
    println!("pre-kill: {kill_after} chunks acked ({} bytes) in {:?}", kill_after * CHUNK, t0.elapsed());

    // KILL the connection mid-transfer.
    drop(client);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    println!("connection killed mid-transfer");

    // Reconnect: query status, resume from the device-reported offset.
    let t1 = Instant::now();
    let client = client_at(addr).await;
    let status = client
        .send_resp::<StatusEndpoint>(&transfer_id)
        .await
        .expect("status");
    println!("post-reconnect status: {status:?}");
    assert_eq!(status.total as usize, TOTAL);
    assert_eq!(status.offset as usize, kill_after * CHUNK);

    let resume_from = status.offset as usize;
    for offset in (resume_from..TOTAL).step_by(CHUNK) {
        let end = (offset + CHUNK).min(TOTAL);
        let ack = client
            .send_resp::<ChunkEndpoint>(&FirmwareChunk {
                id: transfer_id,
                offset: offset as u32,
                total: TOTAL as u32,
                data: payload[offset..end].to_vec(),
            })
            .await
            .expect("chunk ack");
        assert_eq!(ack.offset as usize, end);
    }
    let dt = t1.elapsed();
    println!(
        "resumed+finished {} bytes in {dt:?} => {:.2} MiB/s effective",
        TOTAL - resume_from,
        (TOTAL - resume_from) as f64 / 1024.0 / 1024.0 / dt.as_secs_f64()
    );

    // Verify the assembled payload matches the source byte-for-byte.
    let (assembled, _) = {
        let guard = transfers.lock().unwrap();
        guard.get(&transfer_id).cloned().unwrap()
    };
    assert_eq!(assembled.len(), TOTAL);
    assert_eq!(Sha256::digest(&assembled), expect_sha);
    println!("sha256 verified: assembled == source");
    println!("spike phase 2 OK");

    drop(client);
    device.abort();
    let _ = device.await;
}
