//! HIL parity for the TCP twin (#215 slice 3): the SAME scenarios
//! `conwrt-agent-proto`'s `hil_mock.rs` runs against the std TCP pump,
//! run here against [`agent_session_stream`] — the no_std session loop a
//! firmware app drives over an embassy-net `TcpSocket`. The wire is a
//! real localhost TCP socket (tokio `TcpStream` wrapped as [`StreamIo`],
//! standing in for the embassy socket the same way the mock pipe stands
//! in for CDC), and the client is the real [`AgentClient`] — so passing
//! this suite is passing the suite the std agent passes.

use std::sync::{Arc, Mutex};

use conwrt_agent_io::{StreamIo, agent_session_stream};
use conwrt_agent_proto::controller::{AgentClient, ClientError};
use conwrt_agent_proto::dispatch::{AgentEvent, WireError};
use conwrt_agent_proto::protocol::{CapabilityInfo, DisconnectPolicy, LeaseRequest, LeaseResponse};
use conwrt_agent_proto::server::{ServerCore, UartSink};

use tokio::net::{TcpListener, TcpStream};
use tokio::task;

struct TcpIo(TcpStream);

impl StreamIo for TcpIo {
    type Error = std::io::Error;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        tokio::io::AsyncReadExt::read(&mut self.0, buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        tokio::io::AsyncWriteExt::write(&mut self.0, buf).await
    }
}

/// The firmware-shaped accept loop: one controller at a time, session
/// reset on connect (connection lifecycle drives lease lifecycle), the
/// no_std twin of `run_mock_on`'s per-connection behavior.
async fn spawn_stream_mock_with(server: ServerCore) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr").to_string();
    task::spawn(async move {
        let mut server = server;
        loop {
            let (socket, _) = listener.accept().await.expect("accept");
            server.reset_session();
            let mut io = TcpIo(socket);
            agent_session_stream(&mut io, &mut server).await;
        }
    });
    addr
}

async fn spawn_stream_mock() -> String {
    spawn_stream_mock_with(serial_mock("hil-stream-mock 0.1.0", 1)).await
}

fn serial_mock(agent_version: &str, uarts: u32) -> ServerCore {
    ServerCore::new(
        agent_version,
        Vec::from([CapabilityInfo {
            name: String::from("serial"),
            detail: Vec::from([(String::from("uarts"), uarts.to_string())]),
        }]),
    )
}

fn uart0_exclusive() -> LeaseRequest {
    LeaseRequest {
        resource: "uart0".into(),
        exclusive: true,
        on_disconnect: DisconnectPolicy::Abort,
    }
}

#[tokio::test]
async fn controller_round_trips_handshake_and_capabilities() {
    let addr = spawn_stream_mock().await;
    let mut client = AgentClient::connect(&addr).await.expect("connect");
    let caps = client.handshake("laptop-hil").await.expect("handshake");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].name, "serial");
    assert_eq!(caps[0].detail[0].0, "uarts");

    let caps = client.capabilities().await.expect("capabilities");
    assert_eq!(caps[0].name, "serial");
}

#[tokio::test]
async fn lease_lifecycle_against_the_mcu_brain() {
    let addr = spawn_stream_mock().await;
    let mut client = AgentClient::connect(&addr).await.expect("connect");
    client.handshake("laptop-hil").await.expect("handshake");

    let LeaseResponse::Granted { heartbeat_ms } = client
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant")
    else {
        panic!("first acquire must grant");
    };
    assert_eq!(heartbeat_ms, 1000);

    match client.acquire_lease(uart0_exclusive()).await {
        Err(ClientError::Agent(_)) | Ok(LeaseResponse::Denied { .. }) => {}
        other => panic!("exclusive conflict must be denied, got {other:?}"),
    }

    let released = client.release_lease(1).await.expect("release");
    assert!(released);
    let LeaseResponse::Granted { .. } = client
        .acquire_lease(uart0_exclusive())
        .await
        .expect("re-grant")
    else {
        panic!("released resource must re-grant");
    };
}

#[tokio::test]
async fn connection_loss_expires_leases_like_the_firmware() {
    let addr = spawn_stream_mock().await;

    let mut first = AgentClient::connect(&addr).await.expect("connect 1");
    first.handshake("laptop-1").await.expect("handshake");
    let LeaseResponse::Granted { .. } = first
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant 1")
    else {
        panic!("first session must grant");
    };
    drop(first); // connection loss

    let mut second = AgentClient::connect(&addr).await.expect("connect 2");
    second.handshake("laptop-2").await.expect("handshake");
    let LeaseResponse::Granted { .. } = second
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant 2")
    else {
        panic!("the dead session's lease must not survive the connection");
    };
}

#[tokio::test]
async fn heartbeat_keeps_lease_queryable() {
    let addr = spawn_stream_mock().await;
    let mut client = AgentClient::connect(&addr).await.expect("connect");
    client.handshake("laptop-hil").await.expect("handshake");
    let LeaseResponse::Granted { .. } = client
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant")
    else {
        panic!("acquire must grant");
    };
    client.heartbeat(1).await.expect("heartbeat");
    assert!(matches!(
        client.heartbeat(999).await,
        Err(ClientError::Agent(WireError::UnknownLease(999)))
    ));
}

type SharedWrites = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;

struct SharedSink {
    written: SharedWrites,
}

impl UartSink for SharedSink {
    fn uart_write(&mut self, port: u8, data: &[u8]) -> Result<usize, WireError> {
        self.written.lock().unwrap().push((port, data.to_vec()));
        Ok(data.len())
    }
}

#[tokio::test]
async fn uart_write_is_lease_gated_over_the_wire() {
    let written: SharedWrites = Arc::new(Mutex::new(Vec::new()));
    let server = ServerCore::with_uart(
        "hil-stream-mock 0.1.0",
        Vec::new(),
        Box::new(SharedSink {
            written: Arc::clone(&written),
        }),
    );
    let addr = spawn_stream_mock_with(server).await;
    let mut client = AgentClient::connect(&addr).await.expect("connect");
    client.handshake("laptop-hil").await.expect("handshake");

    match client.uart_write(0, b"AT\r".to_vec()).await {
        Err(ClientError::Agent(WireError::LeaseRequired(resource))) if resource == "uart0" => {}
        other => panic!("pre-lease write must be refused with LeaseRequired, got {other:?}"),
    }
    assert!(
        written.lock().unwrap().is_empty(),
        "refused write must not reach the sink"
    );

    let LeaseResponse::Granted { .. } = client
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant")
    else {
        panic!("acquire must grant");
    };
    let n = client
        .uart_write(0, b"AT\r".to_vec())
        .await
        .expect("leased write");
    assert_eq!(n, 3);
    assert_eq!(*written.lock().unwrap(), vec![(0u8, b"AT\r".to_vec())]);
}

#[tokio::test]
async fn uart_rx_event_flows_to_controller() {
    // A boot banner queued BEFORE the connection must survive the session
    // reset on connect and reach the controller as an unsolicited event —
    // proving the twin drains events after each reply like the std pump.
    let mut server = serial_mock("hil-stream-mock 0.1.0", 1);
    server.push_uart_data(0, b"boot banner");
    let addr = spawn_stream_mock_with(server).await;

    let mut client = AgentClient::connect(&addr).await.expect("connect");
    client.handshake("laptop-hil").await.expect("handshake");
    let _ = client.capabilities().await.expect("capabilities");

    assert_eq!(
        client.try_recv_event(),
        Some(AgentEvent::UartData {
            port: 0,
            data: b"boot banner".to_vec(),
        })
    );
}
