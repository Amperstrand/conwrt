//! The firmware POST pump (#226 slice 4a): the orchestrator that ties
//! the sink-side window ([`ExecutorTransfer`](crate::ExecutorTransfer))
//! to the wire-side [`RecoveryPost`](crate::RecoveryPost) — the
//! composition the F746 task loop runs once the bench leg is
//! authorized.
//!
//! One [`PostPump`] per **wire attempt**. The lifecycle the type
//! encodes (the ring-1/ring-2 HIL conclusions, executable):
//!
//! - the multipart framing is built lazily from the first chunk's
//!   announced `total` — no size can mismatch, nothing exists before
//!   the window binds;
//! - [`step`](PostPump::step) is the whole task-loop body: start the
//!   head once the total is known, drain whatever the window holds,
//!   finish (footer + verdict) the moment the transfer completes;
//! - an **uncommitted** pump follows a window reset freely (a new
//!   controller/transfer id before any wire byte just re-targets the
//!   fresh window);
//! - a **committed** pump whose window got reset answers
//!   [`PumpStep::Superseded`] — the one-request window is spent from
//!   the device's perspective and the verdict is the controller's to
//!   re-arm (power-cycle into recovery), not ours to retry;
//! - a connection loss ends the *attempt*: drop the pump with the
//!   socket. If the device received no bytes (ring-2's pre-POST loss),
//!   the controller re-feeds from offset 0 under a fresh transfer id
//!   (the `WrongTransfer` reset) and a new pump completes the POST.

use crate::multipart::{Multipart, UPLOAD_FIELD};
use crate::post::{PostError, PostOutcome, RecoveryPost};
use crate::transfer::TransferState;

/// What one [`PostPump::step`] accomplished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PumpStep {
    /// No window bound yet — nothing exists, nothing was written.
    Idle,
    /// Head is on the wire and `drained` window bytes moved into the
    /// body this step; more chunks are still expected.
    Streaming {
        /// Window bytes moved to the wire during this step.
        drained: u64,
    },
    /// Finished: the verdict is in (and stays in — further steps
    /// replay it without touching the wire).
    Posted(PostOutcome),
    /// The window was reset (new transfer id) after this pump
    /// committed its request head. The wire attempt is dead — the
    /// one-request server spent its request on the old id. The
    /// controller re-arms (power-cycle) or re-feeds under the new id
    /// with a **fresh** pump if the device saw no bytes.
    Superseded,
}

/// Drain-side orchestrator over one bounded window — what the firmware
/// hands a connected socket to run the recovery POST.
///
/// The boundary token is caller-supplied: `no_std` firmware has no
/// cheap randomness, and any WebKit-shaped token is wire-equivalent
/// (the server delimits, it does not parse).
pub struct PostPump<'a> {
    host: &'a str,
    endpoint: &'a str,
    boundary: &'a str,
    field: &'a str,
    filename: &'a str,
    accept_pattern: Option<&'a str>,
    post: Option<RecoveryPost<'a>>,
    bound_id: Option<u64>,
    verdict: Option<PostOutcome>,
}

impl<'a> PostPump<'a> {
    /// New pump for `host`/`endpoint` with the given boundary token
    /// (`field` = the model default, `filename` = `recovery.bin`).
    #[must_use]
    pub fn new(host: &'a str, endpoint: &'a str, boundary: &'a str) -> Self {
        Self {
            host,
            endpoint,
            boundary,
            field: UPLOAD_FIELD,
            filename: "recovery.bin",
            accept_pattern: None,
            post: None,
            bound_id: None,
            verdict: None,
        }
    }

    /// Override the form field (model JSON `upload_field`, e.g. GL's
    /// `nor__firmware`).
    #[must_use]
    pub fn with_field(mut self, field: &'a str) -> Self {
        self.field = field;
        self
    }

    /// Override the verdict acceptance pattern (model JSON
    /// `upload_response_pattern`).
    #[must_use]
    pub fn with_accept_pattern(mut self, pattern: &'a str) -> Self {
        self.accept_pattern = Some(pattern);
        self
    }

    /// The transfer id this pump has bound (the window it will serve or
    /// served) — `None` before the first step. Callers gate retry logic
    /// on THIS, not on a pre-connect window read: the window may be
    /// re-targeted while a connection is being established (review
    /// round 1, #452 — marking the stale id attempted a second POST
    /// for the freshly-bound one).
    #[must_use]
    pub fn bound_id(&self) -> Option<u64> {
        self.bound_id
    }

    /// Whether the request head has been written — the point of no
    /// return for the one-request window (delegates to the live
    /// [`RecoveryPost`], `false` before the first step).
    #[must_use]
    pub fn committed(&self) -> bool {
        self.post.as_ref().is_some_and(|p| p.committed())
    }

    /// The verdict, once a step reached [`PumpStep::Posted`].
    #[must_use]
    pub fn verdict(&self) -> Option<&PostOutcome> {
        self.verdict.as_ref()
    }

    /// Drive the whole lifecycle one notch: bind + start if needed,
    /// drain the window, finish when the transfer completes.
    ///
    /// `window` is the sink-side door
    /// ([`ExecutorTransfer::window`](crate::ExecutorTransfer::window))
    /// — `None` while no transfer is bound ([`PumpStep::Idle`]).
    ///
    /// # Errors
    /// [`PostError`] straight from the wire stages: a write failure is
    /// a burned attempt (drop this pump with the socket; see module
    /// docs for the two recovery shapes).
    pub async fn step(
        &mut self,
        io: &mut impl crate::post::HttpIo,
        window: Option<&mut TransferState>,
    ) -> Result<PumpStep, PostError> {
        if let Some(verdict) = &self.verdict {
            return Ok(PumpStep::Posted(verdict.clone()));
        }
        let Some(xfer) = window else {
            return Ok(PumpStep::Idle);
        };
        let id = xfer.ack().transfer_id;
        let uncommitted = !self.committed();
        if uncommitted && self.bound_id != Some(id) {
            // (Re)build for the current window: framing from its own
            // announced total, so sizes cannot mismatch. Safe only
            // while nothing is on the wire.
            let mp = Multipart {
                boundary: self.boundary,
                field: self.field,
                filename: self.filename,
                image_len: xfer.total().ok_or(PostError::NoTotal)?,
            };
            let mut post = RecoveryPost::new(mp, self.host, self.endpoint);
            if let Some(pattern) = self.accept_pattern {
                post = post.with_accept_pattern(pattern);
            }
            self.post = Some(post);
            self.bound_id = Some(id);
        }
        let post = self.post.as_mut().expect("built above when unbound");
        if self.bound_id != Some(id) {
            return Ok(PumpStep::Superseded);
        }
        if !post.committed() {
            post.start(io, xfer).await?;
        }
        let drained = post.pump(io, xfer).await?;
        if xfer.is_complete() {
            let outcome = post.finish(io, xfer).await?;
            self.verdict = Some(outcome.clone());
            return Ok(PumpStep::Posted(outcome));
        }
        Ok(PumpStep::Streaming { drained })
    }
}
