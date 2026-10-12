//! Loopback integration tests for the local-std provider.
//!
//! Stub servers are spawned on 127.0.0.1 ephemeral ports (in-process,
//! read-only, nothing leaves the machine) — the "fixture server" pattern
//! from ADR-0011 ring 1. The provider's injectable ports point the TCP
//! probes at them, so `http_get`/`ssh_banner` run their real wire path.

use conwrt_core::capability::LinkProbe;
use conwrt_local_std::LocalProber;
use std::io::Write;
use std::net::{IpAddr, TcpListener};
use std::time::Duration;

fn loopback() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// Bind a loopback listener; spawn a thread that accepts once, replies with
/// `response`, holds the connection briefly, then closes.
fn spawn_once_responder(response: Vec<u8>) -> u16 {
    let listener = TcpListener::bind((loopback(), 0)).expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(&response);
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    port
}

#[tokio::test]
async fn ssh_banner_reads_dropbear_identification() {
    let port = spawn_once_responder(b"SSH-2.0-dropbear_2024.86\r\n".to_vec());
    let mut prober = LocalProber::global().with_ports(0, port);

    let banner = prober
        .ssh_banner(loopback())
        .await
        .unwrap()
        .expect("banner expected");
    assert_eq!(banner.software, "dropbear_2024.86");
}

#[tokio::test]
async fn ssh_banner_none_when_port_closed() {
    let listener = TcpListener::bind((loopback(), 0)).expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut prober = LocalProber::global().with_ports(0, port);
    let banner = prober.ssh_banner(loopback()).await.unwrap();
    assert!(banner.is_none());
}

#[tokio::test]
async fn http_get_parses_recovery_server_response() {
    let response: Vec<u8> =
        b"HTTP/1.0 200 OK\r\nServer: uwWMPre/1.00\r\n\r\n<html><title>REScue</title></html>"
            .to_vec();
    let port = spawn_once_responder(response);
    let mut prober = LocalProber::global().with_ports(port, 0);

    let parsed = prober
        .http_get(loopback(), "/")
        .await
        .unwrap()
        .expect("http response expected");
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.server_header.as_deref(), Some("uwWMPre/1.00"));
    assert_eq!(parsed.title.as_deref(), Some("REScue"));
}

#[tokio::test]
async fn http_get_none_when_port_closed() {
    let listener = TcpListener::bind((loopback(), 0)).expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut prober = LocalProber::global().with_ports(port, 0);
    let parsed = prober.http_get(loopback(), "/").await.unwrap();
    assert!(parsed.is_none());
}

#[tokio::test]
async fn time_sleep_advances() {
    let mut prober = LocalProber::global();
    let start = std::time::Instant::now();
    conwrt_core::capability::Time::sleep_ms(&mut prober, 25).await;
    assert!(start.elapsed() >= Duration::from_millis(20));
}
