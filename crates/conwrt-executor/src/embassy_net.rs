//! `HttpIo` over embassy-net 0.9's `TcpSocket` (#226 slice 3) — the
//! firmware-side transport for [`crate::post::RecoveryPost`].
//!
//! Mirrors conwrt-agent-io's `embassy-net` feature: `read` is inherent
//! on the socket, the write side comes through its
//! `embedded_io_async::Write` impl (version-matched to embassy-net's
//! own requirement — see Cargo.toml).

use alloc::vec::Vec;

use embassy_net::tcp::TcpSocket;

use crate::post::HttpIo;

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
        let mut buf = [0u8; 512];
        loop {
            match TcpSocket::read(&mut self.socket, &mut buf).await {
                Ok(0) => return Ok(()), // server FIN: verdict complete
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e),
            }
        }
    }
}
