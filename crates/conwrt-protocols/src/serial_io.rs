//! Serial I/O adaptation spike (#124) — the M5 seam between the blocking
//! XMODEM engine and an async, `embedded-io-async`-shaped serial driver.
//!
//! # Why this exists
//!
//! [`xmodem`] 0.4's engine is **blocking**: [`crate::xmodem_transfer::send_firmware`]
//! parks its calling thread per block for the whole transfer (minutes at
//! 57.6 kbaud). On an async executor that is the starvation hazard review
//! finding G warned about — a `no_std` compile check proves nothing about
//! whether other tasks keep running or whether the operation can be
//! cancelled. This module provides the adaptation with **host runtime
//! proofs** (`tests/serial_io_spike.rs`):
//!
//! - drive the adapter to completion (verified transfer end-to-end), and
//! - cancel it mid-operation (drop the driver future; the offloaded
//!   attempt drains to a bounded end and closes the transport), while
//! - a co-scheduled heartbeat task keeps ticking throughout (no
//!   starvation).
//!
//! # Shape
//!
//! - [`SerialIo`] is the abstraction embassy targets implement natively
//!   (MCU UART HALs already speak `embedded_io_async`); the trait is the
//!   single seam M5 firmware will program against.
//! - [`ChunkedSerialIo`] adapts a *blocking* transport to that async
//!   surface with an anti-starvation contract: **each poll performs at
//!   most one bounded step** (≤ `max_chunk` bytes, one syscall), then
//!   returns `Pending` until readier. The host test harness drives it by
//!   ticking (re-polling); a device bridge would call [`ChunkedSerialIo::wake`]
//!   from its UART IRQ.
//! - [`send_firmware_verified_async`] is the async driver-level
//!   bounded-retry wrapper: each attempt runs the **blocking engine on a
//!   dedicated OS thread** (`std`-only by construction — the engine must
//!   never run on the async executor), and between attempts the
//!   **receiver-side acceptance check** ([`AcceptanceCheck`]) runs on the
//!   async side over the [`ChunkedSerialIo`] view of the same transport.
//!   A sender-side `Ok` alone never completes the transfer — see the
//!   `mid_stream_nak_advances_without_retransmit` pin: the crate reports
//!   success after a mid-stream NAK while the block was lost
//!   receiver-side.
//! - [`SerialSemantics`] translates Linux `SO_RCVTIMEO` expiry
//!   (`WouldBlock`) into the serial-style `TimedOut` the engine
//!   soft-handles — the pinned `ack_read_timeouts_exhaust_error_budget`
//!   test documents that `WouldBlock` is fatal to the crate.
//!
//! # Test harness choice (documented per #124)
//!
//! Host proofs use a **poll-based mini-executor** (hand-rolled round-robin
//! over `Future::poll`, ~1 ms tick), not an embassy-on-host build: the
//! properties under test — bounded per-poll work, drop-cancellation
//! semantics, cross-thread offload — are executor-independent, and a
//! second executor dependency would not strengthen the evidence. The
//! `no_std` cross-compile of the trait seam is additionally gated in CI
//! (`make rust-ci`).
//!
//! # Cancellation semantics
//!
//! Dropping the [`send_firmware_verified_async`] future mid-attempt
//! cancels: the awaiting side vanishes, the offloaded attempt drains to
//! its bounded end (the transport's read deadline), the worker closes the
//! transport (the peer observes EOF) and exits. No executor thread is
//! parked in the meantime — see that item's docs for the transport
//! requirements.

/// The serial seam M5 firmware programs against (#124).
///
/// Blanket-implemented for anything that speaks
/// [`embedded_io_async::Read`] + [`embedded_io_async::Write`] — embassy
/// UART buffers implement both natively, so driver code written against
/// `SerialIo` ports to the MCU without an adapter layer.
pub trait SerialIo: embedded_io_async::Read + embedded_io_async::Write {}

impl<T> SerialIo for T where T: embedded_io_async::Read + embedded_io_async::Write {}

pub use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

#[cfg(feature = "std")]
mod std_bridge {
    use crate::xmodem_transfer::{
        BlockLength, RetryPolicy, VerifiedError, XmodemError, send_firmware,
    };
    use std::future::{Future, poll_fn};
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Default bytes moved per [`ChunkedSerialIo`] poll step.
    ///
    /// Small enough that a poll step is a bounded, quick syscall; large
    /// enough that a 115200-baud line's kernel buffer drains in a few
    /// steps.
    pub const DEFAULT_MAX_CHUNK: usize = 256;

    /// Async-over-blocking serial adapter with the anti-starvation
    /// contract (#124).
    ///
    /// Every poll performs **at most one bounded step** against the
    /// blocking transport — a read or write of at most [`Self::max_chunk`]
    /// bytes, one syscall — and returns `Pending` on `WouldBlock` (the
    /// contract for "no data yet" on a non-blocking or deadline-bounded
    /// transport). The executor is therefore never parked by this adapter;
    /// between steps every other task runs.
    ///
    /// Readiness is external by design: the adapter stores the waker of
    /// the last poll and exposes [`Self::wake`] — a device-side UART IRQ
    /// (or a host test harness tick) calls it; the adapter never spins on
    /// its own.
    ///
    /// Cancellation-safe: a read/write future that is dropped between
    /// polls leaves no partial state — each poll is an independent
    /// step, and a successful step's byte count is only ever reported
    /// through a `Ready`.
    pub struct ChunkedSerialIo<S> {
        inner: S,
        max_chunk: usize,
        waker: Option<Waker>,
    }

    impl<S> ChunkedSerialIo<S> {
        /// Wrap `inner` with a per-poll chunk bound of `max_chunk` bytes.
        pub fn new(inner: S, max_chunk: usize) -> Self {
            assert!(max_chunk > 0, "max_chunk must be nonzero");
            Self {
                inner,
                max_chunk,
                waker: None,
            }
        }

        /// The chunk bound: maximum bytes one poll may move.
        pub fn max_chunk(&self) -> usize {
            self.max_chunk
        }

        /// Borrow the underlying blocking transport (e.g. to switch it
        /// between deadline and non-blocking modes around a transfer).
        pub fn inner_mut(&mut self) -> &mut S {
            &mut self.inner
        }

        /// Unwrap into the underlying blocking transport.
        pub fn into_inner(self) -> S {
            self.inner
        }

        /// Wake the waker registered by the last `Pending` poll.
        ///
        /// The device-side readiness path: call from the UART IRQ (or a
        /// host harness tick) when data may have arrived.
        pub fn wake(&self) {
            if let Some(w) = &self.waker {
                w.wake_by_ref();
            }
        }
    }

    impl<S: std::io::Read + std::io::Write> embedded_io_async::ErrorType for ChunkedSerialIo<S> {
        type Error = io::Error;
    }

    impl<S: std::io::Read + std::io::Write> embedded_io_async::Read for ChunkedSerialIo<S> {
        /// One bounded read step per poll; `WouldBlock` ⇒ `Pending`.
        ///
        /// Any other error — including `TimedOut` — is terminal for this
        /// read (deadline transports belong behind the engine's
        /// [`SerialSemantics`] wrapper, not here; here `WouldBlock` is the
        /// only "not ready" signal).
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let max = buf.len().min(self.max_chunk);
            poll_fn(|cx| match self.inner.read(&mut buf[..max]) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            })
            .await
        }
    }

    impl<S: std::io::Read + std::io::Write> embedded_io_async::Write for ChunkedSerialIo<S> {
        /// One bounded write step per poll; `WouldBlock`/zero ⇒ `Pending`.
        async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let max = buf.len().min(self.max_chunk);
            poll_fn(|cx| match self.inner.write(&buf[..max]) {
                Ok(0) => {
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            })
            .await
        }

        async fn flush(&mut self) -> io::Result<()> {
            poll_fn(|cx| match self.inner.flush() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            })
            .await
        }
    }

    /// `WouldBlock`-as-`TimedOut` translation for engine-mounted sockets
    /// (#124).
    ///
    /// On Linux, a blocking socket with `SO_RCVTIMEO` surfaces read
    /// deadline expiry as `ErrorKind::WouldBlock` — which the `xmodem`
    /// crate treats as **fatal**; only serial-style `TimedOut` is
    /// soft-handled against the error budget (pinned by
    /// `ack_read_timeouts_exhaust_error_budget` in `tests/xmodem_fitness.rs`).
    /// Mount the engine on [`Self`] so deadline expiry behaves exactly
    /// like a real serial port's read timeout. A real serial port already
    /// yields `TimedOut`, making this wrapper a no-op for it.
    pub struct SerialSemantics<S>(S);

    impl<S> SerialSemantics<S> {
        /// Wrap a deadline-bounded blocking transport for engine use.
        pub fn new(inner: S) -> Self {
            Self(inner)
        }

        /// Unwrap into the underlying transport.
        pub fn into_inner(self) -> S {
            self.0
        }
    }

    impl<S: std::io::Read> std::io::Read for SerialSemantics<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buf) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "read deadline expired (WouldBlock→TimedOut: the XMODEM engine \
                     treats WouldBlock as fatal; serial timeouts must surface as TimedOut)",
                )),
                Err(e) => Err(e),
            }
        }
    }

    impl<S: std::io::Write> std::io::Write for SerialSemantics<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    /// Async receiver-side acceptance check, run after each sender-claimed
    /// success (#124 driver policy).
    ///
    /// A sender-side `Ok` is a claim, not acceptance — after a mid-stream
    /// NAK the crate reports success while the block was lost receiver-side
    /// (`mid_stream_nak_advances_without_retransmit`). The check borrows
    /// the async transport view and answers one question: did the receiver
    /// actually accept the bytes? For U-Boot targets the natural
    /// implementation reads back the bootloader's `crc32 <addr> <size>`
    /// output over the console and compares it against the payload digest
    /// (see `docs/xmodem-receiver-matrix.md`).
    pub trait AcceptanceCheck<S> {
        /// Run the check over the async transport view. The future must be
        /// `Send`: the driver runs on executors that move tasks between
        /// threads.
        fn check<'a>(
            &'a mut self,
            io: &'a mut ChunkedSerialIo<S>,
        ) -> impl Future<Output = bool> + Send + 'a;
    }

    /// Async driver-level bounded-retry transfer (#124): whole-transfer
    /// attempts on a worker thread, receiver-side acceptance between
    /// attempts, the transport returned to the caller in every case.
    ///
    /// - Each attempt clones `payload` and runs [`send_firmware`] (the
    ///   blocking engine) on a **dedicated OS thread** mounted on
    ///   [`SerialSemantics`] — the async executor is never parked by the
    ///   engine (review finding G).
    /// - After a sender-claimed success, `check` runs on the async side
    ///   over a [`ChunkedSerialIo`] view of the same transport; only a
    ///   passing check completes the transfer.
    /// - Between attempts, `policy.restart_delay_ms` passes on the async
    ///   clock (a [`Delay`] future, driven by the executor's tick — no
    ///   timer dependency).
    ///
    /// **Cancellation**: dropping the returned future mid-attempt detaches
    /// the in-flight worker — it drains to its bounded end (the
    /// transport's read deadline; configure one before calling), then
    /// closes the transport and exits. The peer observes EOF. This is the
    /// intended abort semantics for a flash in trouble: close the line,
    /// let the bootloader time out back to its prompt.
    ///
    /// The transport must be `Send + 'static` because attempts run on
    /// another thread; it is handed back in the return value.
    pub async fn send_firmware_verified_async<S, C>(
        transport: S,
        payload: &[u8],
        block_length: BlockLength,
        policy: RetryPolicy,
        mut check: C,
    ) -> (S, Result<usize, VerifiedError>)
    where
        S: std::io::Read + std::io::Write + Send + 'static,
        C: AcceptanceCheck<S>,
    {
        let mut transport = Some(transport);
        let mut attempts = 0u32;
        let mut claimed_successes = 0u32;
        let mut last_claimed_bytes = 0usize;
        let mut last_sender_error: Option<XmodemError> = None;

        while attempts < policy.max_attempts {
            if attempts > 0 {
                Delay::from_millis(policy.restart_delay_ms).await;
            }
            attempts += 1;
            let (rx, _exited) = spawn_attempt(
                transport.take().expect("transport present between phases"),
                payload,
                block_length,
            );
            let (t, result) = recv_attempt(rx).await;
            transport = Some(t);
            match result {
                Ok(bytes) => {
                    claimed_successes += 1;
                    last_claimed_bytes = bytes;
                    let mut io = ChunkedSerialIo::new(
                        transport
                            .take()
                            .expect("transport present for verification"),
                        DEFAULT_MAX_CHUNK,
                    );
                    let accepted = check.check(&mut io).await;
                    transport = Some(io.into_inner());
                    if accepted {
                        return (
                            transport.expect("transport present at completion"),
                            Ok(bytes),
                        );
                    }
                }
                Err(e) => last_sender_error = Some(e),
            }
        }

        // Same terminal classification as the blocking driver: a claimed
        // success that never verified outranks a later sender error — it
        // is the mid-stream-NAK signature.
        let outcome = if claimed_successes > 0 {
            Err(VerifiedError::Unverified {
                attempts,
                bytes_claimed: last_claimed_bytes,
            })
        } else {
            Err(VerifiedError::AttemptsExhausted {
                attempts,
                last: last_sender_error.expect("no success and no error is unreachable"),
            })
        };
        (transport.expect("transport present at completion"), outcome)
    }

    /// One whole-transfer engine attempt on a dedicated thread (#124).
    ///
    /// The engine is blocking by nature; running it inline on an async
    /// executor would starve every other task for the transfer's whole
    /// duration. The worker mounts the transport on [`SerialSemantics`]
    /// (deadline expiry must surface as `TimedOut`, see its docs) and
    /// reports `(transport, result)` back through the channel — handing
    /// the port home whatever happens. If the async side is gone
    /// (cancelled), the send fails and the transport is dropped: the peer
    /// sees EOF, the line closes — the documented abort semantics.
    type AttemptHandoff<S> = (mpsc::Receiver<AttemptReturn<S>>, Arc<AtomicBool>);

    /// The transport comes home in every case — even on engine failure or
    /// worker panic — paired with the engine's verdict.
    type AttemptReturn<S> = (S, Result<usize, XmodemError>);

    fn spawn_attempt<S>(
        transport: S,
        payload: &[u8],
        block_length: BlockLength,
    ) -> AttemptHandoff<S>
    where
        S: std::io::Read + std::io::Write + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&exited);
        let payload = payload.to_vec();
        thread::spawn(move || {
            let mut transport = transport;
            // A panicking engine must still hand the transport home: it is
            // only mutably borrowed here, so it survives the unwind.
            let result = {
                let mut dev = SerialSemantics::new(&mut transport);
                let mut stream = std::io::Cursor::new(&payload);
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    send_firmware(&mut dev, &mut stream, block_length)
                }));
                match r {
                    Ok(res) => res,
                    Err(_) => Err(XmodemError::Io(io::Error::other(
                        "xmodem engine attempt panicked; transport recovered",
                    ))),
                }
            };
            let _ = tx.send((transport, result));
            flag.store(true, Ordering::Release);
        });
        (rx, exited)
    }

    /// Channel receive as a future: one non-blocking `try_recv` per poll.
    async fn recv_attempt<S>(rx: mpsc::Receiver<AttemptReturn<S>>) -> AttemptReturn<S> {
        poll_fn(move |_| match rx.try_recv() {
            Ok(v) => Poll::Ready(v),
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => panic!(
                "engine worker vanished without returning the transport — \
                 this is a bug in the offload bridge, not a transfer failure"
            ),
        })
        .await
    }

    /// Tick-driven delay (no timer dependency): self-wakes so any
    /// re-polling executor (harness tick, embassy alarm) advances it.
    struct Delay {
        until: Instant,
    }

    impl Delay {
        fn from_millis(ms: u64) -> Self {
            Self {
                until: Instant::now() + Duration::from_millis(ms),
            }
        }
    }

    impl Future for Delay {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if Instant::now() >= self.until {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

#[cfg(feature = "std")]
pub use std_bridge::{
    AcceptanceCheck, ChunkedSerialIo, DEFAULT_MAX_CHUNK, SerialSemantics,
    send_firmware_verified_async,
};
