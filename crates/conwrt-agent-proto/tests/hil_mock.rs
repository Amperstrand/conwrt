//! HIL mock e2e (#110): the real controller client ([`AgentClient`])
//! against the MCU agent's brain ([`ServerCore`]) over the TCP wire —
//! the exact code path the STM32 firmware runs, minus the USB pipe.
//! This is the mock stage of the issue's acceptance criterion ("laptop
//! controller ↔ scripted peer (HIL mock, then authorized bench device)").

use std::sync::{Arc, Mutex};

use conwrt_agent_proto::controller::{AgentClient, ClientError};
use conwrt_agent_proto::dispatch::{AgentEvent, WireError};
use conwrt_agent_proto::protocol::{DisconnectPolicy, LeaseRequest, LeaseResponse};
use conwrt_agent_proto::server::{ServerCore, UartSink};
use conwrt_agent_proto::server_tcp::{run_echo_mock_on, run_mock_on, s3_diag_mock, serial_mock};

use tokio::net::TcpListener;
use tokio::task;

async fn spawn_mock_with(server: ServerCore) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr").to_string();
    let mut server = server;
    task::spawn(async move {
        run_mock_on(listener, &mut server).await;
    });
    addr
}

async fn spawn_mock() -> String {
    spawn_mock_with(serial_mock("hil-mock 0.1.0", 1)).await
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
    let addr = spawn_mock().await;
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
    let addr = spawn_mock().await;
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
        Err(conwrt_agent_proto::controller::ClientError::Agent(_))
        | Ok(LeaseResponse::Denied { .. }) => {}
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
    // The firmware resets the ServerCore session when the CDC connection
    // drops; the mock proves the controller-visible consequence: a
    // reconnecting controller gets a fresh lease table (its old lease
    // died with the connection — the Abort default).
    let addr = spawn_mock().await;

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
    let addr = spawn_mock().await;
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
    // heartbeat on an unknown lease is an agent error, proving id 1 is live
    // in the table (UnknownLease would fire for anything else).
    assert!(matches!(
        client.heartbeat(999).await,
        Err(conwrt_agent_proto::controller::ClientError::Agent(
            conwrt_agent_proto::dispatch::WireError::UnknownLease(999)
        ))
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
    let written = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
    let server = ServerCore::with_uart(
        "hil-mock 0.1.0",
        Vec::new(),
        Box::new(SharedSink {
            written: Arc::clone(&written),
        }),
    );
    let addr = spawn_mock_with(server).await;
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
    // reset on connect and reach the controller as an unsolicited event.
    let mut server = serial_mock("hil-mock 0.1.0", 1);
    server.push_uart_data(0, b"boot banner");
    let addr = spawn_mock_with(server).await;

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

#[tokio::test]
async fn uart_echo_round_trips_through_the_scripted_peer() {
    // #110's acceptance shape, mock stage: the controller writes to the
    // agent's UART and the scripted peer echoes it back as an RX event —
    // the full controller → agent → sink → event → controller loop.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr").to_string();
    task::spawn(async move {
        run_echo_mock_on(listener, "echo-mock 0.1.0").await;
    });

    let mut client = AgentClient::connect(&addr).await.expect("connect");
    client.handshake("laptop-hil").await.expect("handshake");
    let LeaseResponse::Granted { .. } = client
        .acquire_lease(uart0_exclusive())
        .await
        .expect("grant")
    else {
        panic!("acquire must grant");
    };

    let n = client
        .uart_write(0, b"ping".to_vec())
        .await
        .expect("leased write");
    assert_eq!(n, 4);

    // the echo returns as an unsolicited event; the follow-up round trip
    // harvests it into the client's event queue
    let _ = client.capabilities().await.expect("capabilities");
    assert_eq!(
        client.try_recv_event(),
        Some(AgentEvent::UartData {
            port: 0,
            data: b"ping".to_vec(),
        })
    );
}

#[tokio::test]
async fn s3_diag_capability_is_served_mock_first() {
    // #111's acceptance shape, mock stage: the agent answers the
    // controller handshake and serves its diagnostic capability — the
    // same ServerCore the ESP32-S3 firmware drives over USB-CDC, with
    // the identical advertisement.
    let addr = spawn_mock_with(s3_diag_mock("conwrt-esp32s3 0.1.0", 48 * 1024)).await;
    let mut client = AgentClient::connect(&addr).await.expect("connect");

    let caps = client.handshake("laptop-s3").await.expect("handshake");
    let expected = vec![
        ("chip".to_string(), "esp32s3".to_string()),
        ("fw".to_string(), "conwrt-esp32s3 0.1.0".to_string()),
        ("heap_bytes".to_string(), (48 * 1024).to_string()),
    ];
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].name, "diag");
    assert_eq!(caps[0].detail, expected);

    let caps = client.capabilities().await.expect("capabilities");
    assert_eq!(caps[0].name, "diag");
    assert_eq!(caps[0].detail, expected);
}

#[tokio::test(start_paused = true)]
async fn echo_mock_expires_leases_on_heartbeat_timeout() {
    // #380: the echo mock must drive the lease clock — a lease that is
    // granted but never heartbeated EXPIRES and reports LeaseExpired.
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_echo_mock_on(listener, "echo-mock 0.1.0").await;
    });

    let mut client = AgentClient::connect(&addr.to_string()).await.unwrap();
    client.handshake("expiry-probe").await.unwrap();
    let resp = client.acquire_lease(uart0_exclusive()).await.unwrap();
    assert!(matches!(resp, LeaseResponse::Granted { .. }));

    // Never heartbeat: the mock's 1s tick burns the budget (3) and the
    // LeaseExpired event must arrive. The capabilities RPC doubles as
    // the read pump (responses and unsolicited events share the wire).
    // Paused-clock sleeps auto-advance; the wall-clock bound only
    // guards against a broken mock, not the expiry itself.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut expired = false;
    while std::time::Instant::now() < deadline {
        let _ = client.capabilities().await;
        while let Some(ev) = client.try_recv_event() {
            if matches!(ev, AgentEvent::LeaseExpired(_)) {
                expired = true;
            }
        }
        if expired {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(expired, "lease never expired over the echo mock");
}
