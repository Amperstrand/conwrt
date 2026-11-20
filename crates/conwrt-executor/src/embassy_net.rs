//! `HttpIo` over embassy-net 0.9's `TcpSocket` (#226 slice 3) — the
//! firmware-side transport for [`crate::post::RecoveryPost`].
//!
//! Mirrors conwrt-agent-io's `embassy-net` feature: `read` is inherent
//! on the socket, the write side comes through its
//! `embedded_io_async::Write` impl (version-matched to embassy-net's
//! own requirement — see Cargo.toml).

use alloc::vec::Vec;

use embassy_net::tcp::TcpSocket;

use crate::post::{HttpIo, retain_verdict_bytes};

/// Recovery-POST transport over an **established** embassy-net TCP
/// connection to the recovery server (U-Boot at `192.168.0.1:80`).
///
/// The firmware connects the socket, then hands it here; [`HttpIo::read_response`]
/// consumes the verdict to EOF (the one-request server FINs after the
/// response body). Thin by design — all protocol shape lives in
/// [`crate::post`]; this type only moves bytes.
pub struct TcpHttpIo<'d> {
    socket: TcpSocket<'d>,
}

impl<'d> TcpHttpIo<'d> {
    /// Wrap a connected socket.
    #[must_use]
    pub fn new(socket: TcpSocket<'d>) -> Self {
        Self { socket }
    }

    /// Unwrap the socket (e.g. to `abort()` it after the verdict —
    /// a burned window must not linger half-open).
    #[must_use]
    pub fn into_inner(self) -> TcpSocket<'d> {
        self.socket
    }
}

impl HttpIo for TcpHttpIo<'_> {
    type Error = embassy_net::tcp::Error;

    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        embedded_io_async::Write::write_all(&mut self.socket, data).await
    }

    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), Self::Error> {
        use embassy_futures::select::select;
        use embassy_time::Timer;
        let mut buf = [0u8; 512];
        // Deadline per READ (not per response): a server that dribbles one
        // byte per 29 s is not producing a verdict either, but a legitimate
        // U-Boot verdict arrives in one burst — a per-read bound catches
        // both the silent hang and the trickle. The Python uploader twin
        // bounds the whole POST at curl -m 400; the firmware bounds the
        // response phase here (the body side is window-driven already).
        // (#232 P2 4298093594: an unbounded loop converts a burned window
        // into a hung task loop — the abort path never ran.)
        const READ_DEADLINE_MS: u64 = 30_000;
        loop {
            let read = TcpSocket::read(&mut self.socket, &mut buf);
            match select(
                read,
                Timer::after(embassy_time::Duration::from_millis(READ_DEADLINE_MS)),
            )
            .await
            {
                embassy_futures::select::Either::First(r) => match r {
                    Ok(0) => return Ok(()), // server FIN: verdict complete
                    // beyond MAX_VERDICT_BYTES: drain, discard — a huge
                    // response is not a verdict, and the 32 KiB heap must
                    // survive the read (review round 2)
                    Ok(n) => {
                        retain_verdict_bytes(out, &buf[..n]);
                    }
                    Err(e) => return Err(e),
                },
                embassy_futures::select::Either::Second(()) => {
                    // The embassy error type has no deadline variant; the
                    // timeout is a burned window exactly like a reset —
                    // the caller aborts the socket either way. Log-side
                    // distinction lives in the firmware task loop.
                    return Err(embassy_net::tcp::Error::ConnectionReset);
                }
            }
        }
    }
}
