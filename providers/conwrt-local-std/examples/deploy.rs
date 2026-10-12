//! Deploy a file to an OpenWrt target via conwrt's own SSH stack
//! (trust ladder + key auth + scp-over-exec) — the dogfooding path used
//! to put Rust binaries onto routers for on-device testing.
//!
//! ```text
//! cargo run -p conwrt-local-std --example deploy -- \
//!     127.0.0.1:2222 tests/integration/.vm_ssh_key local.bin /tmp/remote.bin
//! ```

use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(key), Some(local), Some(remote)) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!("usage: deploy <host:port> <private-key-path> <local-file> <remote-path>");
        std::process::exit(2);
    };

    let target = SshTarget {
        addr,
        user: "root".into(),
        auth: SshAuth::KeyFile {
            path: PathBuf::from(key),
            passphrase: None,
        },
    };
    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect");

    let data = std::fs::read(&local).expect("read local file");
    session.scp_upload(&data, &remote).await.expect("upload");
    println!(
        "uploaded {} ({} bytes) to {} — host key {}",
        local,
        data.len(),
        remote,
        session.presented_key.fingerprint
    );
}
