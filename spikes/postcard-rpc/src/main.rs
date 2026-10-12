//! # postcard-rpc spike (#107, ADR-0004)
//!
//! Viability question: can postcard-rpc 0.12 drive a **TCP** transport with
//! a thin custom wire (the crate ships no TCP impl), using COBS framing
//! identical to the USB-CDC/serial path ("one codec everywhere")?
//!
//! This binary runs BOTH sides in-process over a loopback TCP socket:
//! a device-side `Server` with an `EchoEndpoint` (String -> String) and a
//! host-side `HostClient`, then measures round-trip latency. The custom
//! wire-glue line count feeds ADR-0004's kill-criteria (<300 LOC rule).

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

// ---------------------------------------------------------------------------
// Protocol definition (what a real conwrt-agent-proto crate would contain)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Serialize, Deserialize, postcard_schema::Schema)]
pub enum WireErr {
    UnknownEndpoint,
    BadRequest,
}

endpoints! {
    list = ENDPOINT_LIST;
    | EndpointTy   | RequestTy | ResponseTy | Path    |
    | ------------ | --------- | ---------- | ------- |
    | EchoEndpoint | String    | String     | "/echo" |
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
// Host-side TCP wire (host WireTx/WireRx/WireSpawn; mirrors the in-tree
// serial COBS wire byte-for-byte)
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
        pub buf: Box<[u8; 1024]>,
        pub acc: Box<CobsAccumulator<1024>>,
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
// Device-side TCP wire (server WireTx/WireRx traits; COBS again)
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
        pub buf: Box<[u8; 1024]>,
        pub acc: Box<CobsAccumulator<1024>>,
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
// Device application: dispatch with an echo handler
// ---------------------------------------------------------------------------

pub struct Ctx;

async fn echo_handler(_ctx: &mut Ctx, _hdr: VarHeader, req: String) -> String {
    req
}

define_dispatch! {
    app: SingleDispatcher;
    spawn_fn: spawn_fn;
    tx_impl: device_wire::dispatch_impl::WireTxImpl;
    spawn_impl: ServerSpawn;
    context: Ctx;

    endpoints: {
        list: ENDPOINT_LIST;

        | EndpointTy   | kind  | handler      |
        | -----------  | ----- | ------------ |
        | EchoEndpoint | async | echo_handler |
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
// Main: device (listener) + host (client) in one process over loopback TCP
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Device side
    let device = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (rx, tx) = tokio::io::split(socket);
        let stx = device_wire::ServerTcpTx {
            tx: Arc::new(tokio::sync::Mutex::new(tx)),
            log_ctr: std::sync::atomic::AtomicU32::new(0),
        };
        let srx = device_wire::ServerTcpRx {
            rx,
            buf: Box::new([0u8; 1024]),
            acc: Box::new(CobsAccumulator::new()),
            pending: VecDeque::new(),
        };
        let dispatch = SingleDispatcher::new(Ctx, device_wire::ServerSpawn);
        let mut server: Server<_, _, Box<[u8]>, _> =
            Server::new(stx, srx, vec![0u8; 4096].into(), dispatch, VarKeyKind::Key8);
        let _ = server.run().await;
    });

    // Host side
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (rx, tx) = tokio::io::split(socket);
    let client: HostClient<WireErr> = HostClient::new_with_wire(
        host_wire::TcpWireTx { tx },
        host_wire::TcpWireRx {
            rx,
            buf: Box::new([0u8; 1024]),
            acc: Box::new(CobsAccumulator::new()),
            pending: VecDeque::new(),
        },
        host_wire::TokioSpawn,
        VarSeqKind::Seq1,
        "err",
        8,
    );

    // One correctness round-trip
    let resp = client
        .send_resp::<EchoEndpoint>(&"hello postcard-rpc over tcp".to_string())
        .await
        .expect("round trip");
    println!("echo: {resp:?}");
    assert_eq!(resp, "hello postcard-rpc over tcp");

    // Latency measurement
    const N: u32 = 1_000;
    let t0 = Instant::now();
    for i in 0..N {
        let resp = client
            .send_resp::<EchoEndpoint>(&format!("ping-{i}"))
            .await
            .expect("round trip");
        assert_eq!(resp, format!("ping-{i}"));
    }
    let dt = t0.elapsed();
    println!("{N} round-trips in {dt:?} => {:.2?}/rtt", dt / N);

    drop(client);
    let _ = device.await;
    println!("spike OK");
}
