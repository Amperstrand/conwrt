//! Ring-2 test: the SSH provider against a **real OpenWrt Dropbear** in the
//! QEMU integration VM (ADR-0011). Gated behind `CONWRT_QEMU_VM=1` plus
//! reachability of the VM's forwarded SSH port — CI never runs this; it is
//! the local virtualized stage between the in-process fixture and physical
//! hardware.
//!
//! Boot the VM first (from the repo root):
//! ```text
//! scripts/local-tests.sh integration   # or boot_vm-equivalent qemu invocation
//! CONWRT_QEMU_VM=1 cargo test -p conwrt-local-std --test qemu_dropbear -- --nocapture
//! ```

use conwrt_core::capability::LinkProbe;
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_local_std::LocalProber;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

const VM_ADDR: &str = "127.0.0.1:2222";

fn vm_key_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/integration/.vm_ssh_key")
}

fn vm_available() -> bool {
    if std::env::var("CONWRT_QEMU_VM").ok().as_deref() != Some("1") {
        return false;
    }
    std::net::TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 2222),
        std::time::Duration::from_secs(2),
    )
    .is_ok()
}

fn vm_target() -> SshTarget {
    SshTarget {
        addr: VM_ADDR.to_string(),
        user: "root".to_string(),
        auth: SshAuth::KeyFile {
            path: vm_key_path(),
            passphrase: None,
        },
    }
}

async fn vm_session() -> conwrt_local_std::ssh::SshSession {
    let mut store = MemoryTrustStore::new();
    connect(
        &vm_target(),
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to VM dropbear")
}

#[tokio::test]
async fn dropbear_exec_and_exit_codes() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let session = vm_session().await;
    assert!(
        session.presented_key.key_algo.contains("ssh-ed25519")
            || session.presented_key.key_algo.contains("rsa"),
        "unexpected host key algo: {}",
        session.presented_key.key_algo
    );

    let release = session
        .exec("cat /etc/openwrt_release")
        .await
        .expect("exec");
    assert_eq!(release.exit_code, Some(0));
    let text = String::from_utf8_lossy(&release.stdout);
    assert!(text.contains("OpenWrt"), "got: {text}");
    assert!(text.contains("25.12"), "got: {text}");

    assert_eq!(session.exec("true").await.expect("true").exit_code, Some(0));
    assert_eq!(
        session.exec("false").await.expect("false").exit_code,
        Some(1)
    );
}

#[tokio::test]
async fn dropbear_scp_roundtrip() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let session = vm_session().await;

    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 253) as u8).collect();
    let remote = format!("/tmp/conwrt-rs-{}.bin", std::process::id());
    session.scp_upload(&payload, &remote).await.expect("upload");

    let check = session
        .exec(&format!("sha256sum {remote}"))
        .await
        .expect("sha256sum");
    assert_eq!(check.exit_code, Some(0));
    assert!(
        !check.stdout.is_empty(),
        "sha256sum produced no output: {:?}",
        String::from_utf8_lossy(&check.stderr)
    );

    let downloaded = session.scp_download(&remote).await.expect("download");
    assert_eq!(downloaded.len(), payload.len());
    assert_eq!(downloaded, payload);

    session
        .exec(&format!("rm -f {remote}"))
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn dropbear_banner_classifies_openwrt_via_probe() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let mut prober = LocalProber::global().with_ports(0, 2222);
    let banner = prober
        .ssh_banner(IpAddr::from([127, 0, 0, 1]))
        .await
        .expect("probe")
        .expect("banner from real dropbear");
    assert!(
        banner.software.starts_with("dropbear"),
        "got: {}",
        banner.software
    );
}
