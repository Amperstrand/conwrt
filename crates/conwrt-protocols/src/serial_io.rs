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

    /// Cloneable readiness handle for [`ChunkedSerialIo`] (#124 review:
    /// the wake path must be callable while the adapter is exclusively
    /// borrowed by an in-flight read/write future — an IRQ cannot take
    /// `&mut`).
    ///
    /// The handle holds the waker registered by the adapter's last
    /// `Pending` poll; `wake()` rouses it from any context (UART IRQ,
    /// worker thread, harness tick). Last registration wins; the driver
    /// keeps at most one adapter operation in flight at a time.
    #[derive(Clone)]
    pub struct Readiness(Arc<std::sync::Mutex<Option<Waker>>>);

    impl Readiness {
        fn new() -> Self {
            Self(Arc::new(std::sync::Mutex::new(None)))
        }

        fn register(&self, waker: &Waker) {
            *self.0.lock().unwrap() = Some(waker.clone());
        }

        /// Wake the task registered by the last `Pending` poll (no-op if
        /// none). Idempotent and callable from any thread.
        pub fn wake(&self) {
            if let Some(w) = self.0.lock().unwrap().as_ref() {
                w.wake_by_ref();
            }
        }
    }

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
    /// the last poll, exposed as a cloneable [`Self::readiness`] handle
    /// (and a convenience [`Self::wake`]) — a device-side UART IRQ (or a
    /// host test harness tick) calls it while a future holds the adapter;
    /// the adapter never spins on its own.
    ///
    /// Cancellation-safe: a read/write future that is dropped between
    /// polls leaves no partial state — each poll is an independent
    /// step, and a successful step's byte count is only ever reported
    /// through a `Ready`.
    pub struct ChunkedSerialIo<S> {
        inner: S,
        max_chunk: usize,
        readiness: Readiness,
    }

    impl<S> ChunkedSerialIo<S> {
        /// Wrap `inner` with a per-poll chunk bound of `max_chunk` bytes.
        pub fn new(inner: S, max_chunk: usize) -> Self {
            assert!(max_chunk > 0, "max_chunk must be nonzero");
            Self {
                inner,
                max_chunk,
                readiness: Readiness::new(),
            }
        }

        /// The chunk bound: maximum bytes one poll may move.
        pub fn max_chunk(&self) -> usize {
            self.max_chunk
        }

        /// A cloneable readiness handle: wake the adapter's pending
        /// operation from any context (IRQ, worker, harness) — including
        /// while a read/write future exclusively borrows the adapter.
        pub fn readiness(&self) -> Readiness {
            self.readiness.clone()
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
        /// host harness tick) when data may have arrived. Equivalent to
        /// [`Self::readiness`]`.wake()`; prefer the handle from IRQ
        /// context where the adapter is mutably borrowed.
        pub fn wake(&self) {
            self.readiness.wake();
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
                    self.readiness.register(cx.waker());
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
                    self.readiness.register(cx.waker());
                    Poll::Pending
                }
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.readiness.register(cx.waker());
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
                    self.readiness.register(cx.waker());
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
    ///   engine (review finding G). The worker signals a shared
    ///   [`Readiness`] when it hands the result home, so wake-driven
    ///   executors progress without polling.
    /// - After a sender-claimed success, `check` runs on the async side
    ///   over a [`ChunkedSerialIo`] view of the same transport; only a
    ///   passing check completes the transfer.
    /// - Before every attempt after the first, `rearm` runs over the
    ///   same view: a real receiver does NOT re-enter receive mode by
    ///   itself — U-Boot returns to its prompt after an aborted `loadx`
    ///   and must be told to receive again. The hook issues the
    ///   receiver command (e.g. `loadx <addr>`) and waits for the ready
    ///   banner. Between attempts, `policy.restart_delay_ms` passes on
    ///   the async clock (a [`Delay`] future — no timer dependency).
    ///
    /// **Cancellation**: dropping the returned future mid-attempt detaches
    /// the in-flight worker — it drains to its bounded end, then closes
    /// the transport and exits. The peer observes EOF. This is the
    /// intended abort semantics for a flash in trouble: close the line,
    /// let the bootloader time out back to its prompt.
    ///
    /// **Transport deadlines (both required)**: a READ deadline bounds
    /// the engine's ACK waits (budget-consumed as `TimedOut`, see
    /// [`SerialSemantics`]); a WRITE deadline bounds the engine's
    /// writes — if the peer stops draining mid-transfer, the blocking
    /// write fails fatally and the worker ends promptly. Without a
    /// write deadline a stalled peer could wedge the worker
    /// indefinitely, breaking the bounded-cancellation promise for
    /// firmware-sized payloads.
    ///
    /// The transport must be `Send + 'static` because attempts run on
    /// another thread; it is handed back in the return value.
    pub async fn send_firmware_verified_async<S, C, R>(
        transport: S,
        payload: &[u8],
        block_length: BlockLength,
        policy: RetryPolicy,
        mut check: C,
        mut rearm: R,
    ) -> (S, Result<usize, VerifiedError>)
    where
        S: std::io::Read + std::io::Write + Send + 'static,
        C: AcceptanceCheck<S>,
        R: ReceiverReArm<S>,
    {
        let mut transport = Some(transport);
        let mut attempts = 0u32;
        let mut claimed_successes = 0u32;
        let mut last_claimed_bytes = 0usize;
        let mut last_sender_error: Option<XmodemError> = None;

        while attempts < policy.max_attempts {
            if attempts > 0 {
                Delay::from_millis(policy.restart_delay_ms).await;
                let mut io = ChunkedSerialIo::new(
                    transport.take().expect("transport present between phases"),
                    DEFAULT_MAX_CHUNK,
                );
                rearm.rearm(&mut io).await;
                transport = Some(io.into_inner());
            }
            attempts += 1;
            let (rx, _exited, done) = spawn_attempt(
                transport.take().expect("transport present between phases"),
                payload,
                block_length,
            );
            let (t, result) = recv_attempt(rx, done).await;
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

    /// Between-attempts receiver re-arm (#124 review: a real receiver
    /// does not re-enter receive mode by itself).
    ///
    /// After a failed (or refused) attempt most bootloaders sit at their
    /// prompt: U-Boot prints `## Binary (xmodem) download aborted` and
    /// waits for a command — it will never emit a fresh `C`. The driver
    /// runs this hook over the transport view before every subsequent
    /// attempt; the implementation issues the receiver's load command
    /// (e.g. `loadx <addr>`) and waits for its ready banner.
    pub trait ReceiverReArm<S> {
        /// Put the receiver back into XMODEM receive mode.
        fn rearm<'a>(
            &'a mut self,
            io: &'a mut ChunkedSerialIo<S>,
        ) -> impl Future<Output = ()> + Send + 'a;
    }

    /// No-op [`ReceiverReArm`] for receivers that DO re-enter receive
    /// mode on their own (scripted test receivers; a bootloader still
    /// looping inside its receive-timeout window).
    pub struct NoReArm;

    impl<S: Send> ReceiverReArm<S> for NoReArm {
        async fn rearm(&mut self, _io: &mut ChunkedSerialIo<S>) {}
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
    type AttemptHandoff<S> = (mpsc::Receiver<AttemptReturn<S>>, Arc<AtomicBool>, Readiness);

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
        let done = Readiness::new();
        let done_wake = done.clone();
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
            done_wake.wake();
            flag.store(true, Ordering::Release);
        });
        (rx, exited, done)
    }

    /// Channel receive as a future: one non-blocking `try_recv` per
    /// poll, with the waker registered for the worker's post-send wake
    /// (register, then re-check — a send landing between the two
    /// cannot be missed).
    async fn recv_attempt<S>(
        rx: mpsc::Receiver<AttemptReturn<S>>,
        done: Readiness,
    ) -> AttemptReturn<S> {
        poll_fn(move |cx| match rx.try_recv() {
            Ok(v) => Poll::Ready(v),
            Err(mpsc::TryRecvError::Empty) => {
                done.register(cx.waker());
                match rx.try_recv() {
                    Ok(v) => Poll::Ready(v),
                    Err(mpsc::TryRecvError::Empty) => Poll::Pending,
                    Err(mpsc::TryRecvError::Disconnected) => panic!(
                        "engine worker vanished without returning the transport — \
                         this is a bug in the offload bridge, not a transfer failure"
                    ),
                }
            }
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
    AcceptanceCheck, ChunkedSerialIo, DEFAULT_MAX_CHUNK, NoReArm, Readiness, ReceiverReArm,
    SerialSemantics, send_firmware_verified_async,
};
