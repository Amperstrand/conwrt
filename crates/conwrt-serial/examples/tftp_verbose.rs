//! Standalone verbose TFTP shell (diagnostics): serves one directory on
//! a fixed bind with per-packet stderr logging. Usage:
//!   cargo run -p conwrt-serial --example tftp_verbose -- 192.168.1.10:69 /srv/tftp-gs1900

use std::net::SocketAddr;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bind: SocketAddr = args
        .get(1)
        .expect("bind addr arg")
        .parse()
        .expect("socket addr");
    let root = Path::new(
        args.get(2)
            .map(|s| s.as_str())
            .unwrap_or("/srv/tftp-gs1900"),
    );
    eprintln!("verbose tftp serving {root:?} on {bind}");
    let errors = conwrt_serial::tftp::serve_until_verbose(bind, root, &|| false);
    eprintln!("errors: {errors:?}");
}
