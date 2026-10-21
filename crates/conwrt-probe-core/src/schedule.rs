//! Probe scheduling — the pure, time-parameterized state machine under
//! `router-probe.py::probe_router`'s probe sequencing (and the ordered
//! gates of `scripts/flash/detect.py`).
//!
//! The Python flow is: instant passive probes (link, ARP), then FOUR
//! capture listeners running CONCURRENTLY (failsafe broadcast, ICMPv6
//! RA, DHCP, TFTP — the source's own comment: "sequential would cost
//! up to 4x the timeout"), then active probes (HTTP GET/HEAD, ping,
//! SSH, SSH failsafe), then classification. Concurrency there is not a
//! wall-clock nicety: the packets are transient boot-window events, so
//! a listener that starts late MISSES its evidence. The scheduler
//! models that shape directly — [`Stage::Concurrent`] starts every
//! member together and the stage ends when the last member concludes.
//!
//! The caller owns the clock (ADR-0002 — time is a capability) and
//! performs the actual probe I/O; the scheduler decides which probes
//! are live and when their budgets expire.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// One probe in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStep {
    /// Which probe this is.
    pub kind: ProbeKind,
    /// Budget in milliseconds; 0 = instant (no waiting room).
    pub timeout_ms: u64,
}

/// The probe kinds the source of truth runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// `probe_link_state` — instant, local sysfs/ifconfig read.
    LinkState,
    /// `probe_arp` — instant, local ARP table read.
    Arp,
    /// `probe_failsafe_broadcast` — bounded UDP 4919 capture.
    FailsafeBroadcast,
    /// `probe_icmpv6_ra` — bounded RA capture (`min(passive, 5s)`).
    Icmpv6Ra,
    /// `probe_dhcp` — bounded DHCP capture (`passive_timeout`).
    Dhcp,
    /// `probe_tftp` — bounded TFTP RRQ capture (`passive_timeout`).
    Tftp,
    /// `probe_http_get` — active HTTP GET (3s).
    HttpGet,
    /// `probe_http_head` — active HTTP HEAD (3s).
    HttpHead,
    /// `probe_ping` — ICMP echo (2s).
    Ping,
    /// `probe_ssh` — SSH release-file probe (8s).
    Ssh,
    /// `probe_ssh_failsafe` — SSH failsafe markers (8s).
    SshFailsafe,
}

/// One stage of the plan: a probe alone, or a group whose members all
/// start together and must all conclude before the next stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// A single probe; the next stage starts when it concludes.
    Alone(ProbeStep),
    /// Probes started together (the passive capture quad) — the
    /// source runs them in one thread pool so no listener misses its
    /// transient boot-window packets by starting late.
    Concurrent(&'static [ProbeStep]),
}

/// What the scheduler wants the driver to do. One event per
/// [`ProbeScheduler::poll`] — poll in a loop until it returns
/// [`ProbeEvent::Waiting`] or [`ProbeEvent::Complete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeEvent {
    /// Begin this probe now (its budget started at the poll instant).
    /// A concurrent stage emits one `Start` per member on consecutive
    /// polls.
    Start(ProbeKind),
    /// The probe's budget expired — abandon it (the Python future
    /// timeouts; in a concurrent stage the remaining members keep
    /// running).
    TimedOut(ProbeKind),
    /// The named probe is still within its budget — keep driving it.
    /// Concurrent stages surface their longest-running member.
    Waiting(ProbeKind),
    /// Every stage has fully run; proceed to classification.
    Complete,
}

/// Time-bounded stage-driven probe scheduler with an injected clock.
///
/// ```ignore
/// let mut sched = ProbeScheduler::new(plan);
/// loop {
///     match sched.poll(now) {
///         ProbeEvent::Start(kind) => { /* begin it */ }
///         ProbeEvent::Waiting(kind) => { /* keep driving it */ }
///         ProbeEvent::TimedOut(kind) => { /* drop its future */ }
///         ProbeEvent::Complete => break,
///     }
///     // when a probe concludes on its own:
///     sched.finish(kind);
/// }
/// ```
#[derive(Debug)]
pub struct ProbeScheduler {
    stages: Vec<Stage>,
    next_stage: usize,
    /// Entered-but-not-yet-announced probes of the current stage:
    /// (step, started_at) — each gets exactly one `Start` event.
    pending: Vec<(ProbeStep, u64)>,
    /// Announced, running probes: (step, started_at) — removed on
    /// `finish` or timeout.
    live: Vec<(ProbeStep, u64)>,
    stage_entered: bool,
}

impl ProbeScheduler {
    /// New scheduler over `stages`; the first [`Self::poll`] starts
    /// the first stage. See [`default_plan`] for the source-of-truth
    /// sequence and budgets.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self {
            stages,
            next_stage: 0,
            pending: Vec::new(),
            live: Vec::new(),
            stage_entered: false,
        }
    }

    /// Advance the machine at time `now_ms` (caller-injected clock).
    #[must_use]
    pub fn poll(&mut self, now_ms: u64) -> ProbeEvent {
        if !self.stage_entered {
            if self.next_stage >= self.stages.len() {
                return ProbeEvent::Complete;
            }
            self.enter_stage(self.next_stage, now_ms);
        }
        // Announce every entered member before anything else, so a
        // concurrent stage's members all arm promptly (one Start each).
        if let Some((step, started_at)) = self.pending.first().copied() {
            self.pending.remove(0);
            self.live.push((step, started_at));
            return ProbeEvent::Start(step.kind);
        }
        // All members announced: expired budgets report first.
        if let Some(index) = self.live.iter().position(|&(step, at)| {
            step.timeout_ms > 0 && now_ms.saturating_sub(at) >= step.timeout_ms
        }) {
            let (step, _) = self.live.remove(index);
            return ProbeEvent::TimedOut(step.kind);
        }
        if let Some(&(step, _)) = self.live.first() {
            return ProbeEvent::Waiting(step.kind);
        }
        // Current stage drained: enter the next one (or complete).
        self.stage_entered = false;
        self.next_stage += 1;
        if self.next_stage >= self.stages.len() {
            return ProbeEvent::Complete;
        }
        self.enter_stage(self.next_stage, now_ms);
        let (step, started_at) = self.pending.remove(0);
        self.live.push((step, started_at));
        ProbeEvent::Start(step.kind)
    }

    /// The driver reports this probe concluded (answered or failed on
    /// its own — any result). No-op for a probe that is not live.
    pub fn finish(&mut self, kind: ProbeKind) {
        self.live.retain(|&(step, _)| step.kind != kind);
    }

    /// Which probes are currently live (announced, within budget).
    #[must_use]
    pub fn live_probes(&self) -> Vec<ProbeKind> {
        self.live.iter().map(|&(step, _)| step.kind).collect()
    }

    /// Fill `pending` from stage `index` and mark the stage entered.
    fn enter_stage(&mut self, index: usize, now_ms: u64) {
        match self.stages[index] {
            Stage::Alone(step) => self.pending = vec![(step, now_ms)],
            Stage::Concurrent(steps) => {
                self.pending = steps.iter().map(|&step| (step, now_ms)).collect();
            }
        }
        self.stage_entered = true;
    }
}

/// The `probe_router` plan: instant passive reads, the four capture
/// listeners as ONE concurrent stage (all driven by `passive_timeout`,
/// RA additionally capped at 5s), then active probes with the Python's
/// fixed budgets (curl 3s; ping 2s; SSH 8s; `passive_timeout` default
/// 10s).
#[must_use]
pub fn default_plan(passive_timeout_ms: u64) -> Vec<Stage> {
    let ra_budget = passive_timeout_ms.min(5_000);
    let captures: &'static [ProbeStep] = Box::leak(Box::new([
        ProbeStep {
            kind: ProbeKind::FailsafeBroadcast,
            timeout_ms: passive_timeout_ms,
        },
        ProbeStep {
            kind: ProbeKind::Icmpv6Ra,
            timeout_ms: ra_budget,
        },
        ProbeStep {
            kind: ProbeKind::Dhcp,
            timeout_ms: passive_timeout_ms,
        },
        ProbeStep {
            kind: ProbeKind::Tftp,
            timeout_ms: passive_timeout_ms,
        },
    ]));
    vec![
        Stage::Alone(ProbeStep {
            kind: ProbeKind::LinkState,
            timeout_ms: 0,
        }),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::Arp,
            timeout_ms: 0,
        }),
        Stage::Concurrent(captures),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::HttpGet,
            timeout_ms: 3_000,
        }),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::HttpHead,
            timeout_ms: 3_000,
        }),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::Ping,
            timeout_ms: 2_000,
        }),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::Ssh,
            timeout_ms: 8_000,
        }),
        Stage::Alone(ProbeStep {
            kind: ProbeKind::SshFailsafe,
            timeout_ms: 8_000,
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_starts(sched: &mut ProbeScheduler, t: u64) -> Vec<ProbeKind> {
        let mut started = Vec::new();
        while let ProbeEvent::Start(kind) = sched.poll(t) {
            started.push(kind);
        }
        started
    }

    #[test]
    fn plan_starts_each_step_in_source_order() {
        let mut sched = ProbeScheduler::new(default_plan(10_000));
        let mut t = 1_000;
        let mut seen: Vec<ProbeKind> = Vec::new();
        loop {
            match sched.poll(t) {
                ProbeEvent::Start(kind) => seen.push(kind),
                ProbeEvent::Waiting(_) | ProbeEvent::TimedOut(_) => {}
                ProbeEvent::Complete => break,
            }
            sched.finish(seen.last().copied().expect("a probe must have started"));
            t += 1;
        }
        assert_eq!(
            seen,
            vec![
                ProbeKind::LinkState,
                ProbeKind::Arp,
                ProbeKind::FailsafeBroadcast,
                ProbeKind::Icmpv6Ra,
                ProbeKind::Dhcp,
                ProbeKind::Tftp,
                ProbeKind::HttpGet,
                ProbeKind::HttpHead,
                ProbeKind::Ping,
                ProbeKind::Ssh,
                ProbeKind::SshFailsafe,
            ]
        );
    }

    #[test]
    fn capture_quad_starts_concurrently_and_overlaps() {
        // review round 2: the four listeners arm together — DHCP does
        // not wait out failsafe's timeout first (transient boot
        // packets are missed by late listeners)
        let mut sched = ProbeScheduler::new(default_plan(10_000));
        let instant = drain_starts(&mut sched, 0);
        assert_eq!(instant, vec![ProbeKind::LinkState]);
        sched.finish(ProbeKind::LinkState);
        assert_eq!(drain_starts(&mut sched, 0), vec![ProbeKind::Arp],);
        sched.finish(ProbeKind::Arp);
        let quad = drain_starts(&mut sched, 0);
        assert_eq!(
            quad,
            vec![
                ProbeKind::FailsafeBroadcast,
                ProbeKind::Icmpv6Ra,
                ProbeKind::Dhcp,
                ProbeKind::Tftp,
            ]
        );
        assert_eq!(sched.live_probes().len(), 4, "all four run together");
        // RA (5s budget) times out first, alone; the rest keep waiting
        assert_eq!(sched.poll(5_000), ProbeEvent::TimedOut(ProbeKind::Icmpv6Ra));
        assert_eq!(
            sched.poll(5_000),
            ProbeEvent::Waiting(ProbeKind::FailsafeBroadcast)
        );
        // one member concluding does not end the stage
        sched.finish(ProbeKind::Dhcp);
        assert_eq!(
            sched.poll(5_000),
            ProbeEvent::Waiting(ProbeKind::FailsafeBroadcast)
        );
    }

    #[test]
    fn stage_ends_only_when_every_member_concludes() {
        let mut sched = ProbeScheduler::new(default_plan(10_000));
        assert_eq!(drain_starts(&mut sched, 0), vec![ProbeKind::LinkState]);
        sched.finish(ProbeKind::LinkState);
        assert_eq!(drain_starts(&mut sched, 0), vec![ProbeKind::Arp]);
        sched.finish(ProbeKind::Arp);
        drain_starts(&mut sched, 0);
        sched.finish(ProbeKind::Icmpv6Ra);
        sched.finish(ProbeKind::Dhcp);
        // both 10s members still live -> still waiting at +9s
        assert_eq!(
            sched.poll(9_000),
            ProbeEvent::Waiting(ProbeKind::FailsafeBroadcast)
        );
        // last two conclude -> next stage starts (http_get)
        sched.finish(ProbeKind::FailsafeBroadcast);
        sched.finish(ProbeKind::Tftp);
        assert_eq!(sched.poll(9_001), ProbeEvent::Start(ProbeKind::HttpGet));
    }

    #[test]
    fn budget_expiry_times_out_and_moves_on() {
        let plan = vec![Stage::Alone(ProbeStep {
            kind: ProbeKind::Dhcp,
            timeout_ms: 30_000,
        })];
        let mut sched = ProbeScheduler::new(plan);
        assert_eq!(sched.poll(0), ProbeEvent::Start(ProbeKind::Dhcp));
        // still in budget at +29s
        assert_eq!(sched.poll(29_000), ProbeEvent::Waiting(ProbeKind::Dhcp));
        // expired at +30s (>= semantics: the Python tcpdump timeout)
        assert_eq!(sched.poll(30_000), ProbeEvent::TimedOut(ProbeKind::Dhcp));
        // next poll: plan exhausted
        assert_eq!(sched.poll(30_000), ProbeEvent::Complete);
    }

    #[test]
    fn finish_short_circuits_the_budget() {
        let plan = vec![
            Stage::Alone(ProbeStep {
                kind: ProbeKind::HttpGet,
                timeout_ms: 3_000,
            }),
            Stage::Alone(ProbeStep {
                kind: ProbeKind::Ping,
                timeout_ms: 2_000,
            }),
        ];
        let mut sched = ProbeScheduler::new(plan);
        assert_eq!(sched.poll(0), ProbeEvent::Start(ProbeKind::HttpGet));
        sched.finish(ProbeKind::HttpGet); // curl answered in 10ms
        assert_eq!(sched.poll(10), ProbeEvent::Start(ProbeKind::Ping));
        sched.finish(ProbeKind::Ping);
        assert_eq!(sched.poll(11), ProbeEvent::Complete);
    }

    #[test]
    fn empty_plan_completes_immediately() {
        let mut sched = ProbeScheduler::new(Vec::new());
        assert_eq!(sched.poll(0), ProbeEvent::Complete);
    }

    fn capture_quad(plan: &[Stage]) -> &'static [ProbeStep] {
        let Stage::Concurrent(captures) = &plan[2] else {
            panic!("stage 3 must be the capture quad");
        };
        captures
    }

    #[test]
    fn ra_budget_is_capped_at_five_seconds() {
        let captures = capture_quad(&default_plan(10_000));
        assert_eq!(
            captures
                .iter()
                .find(|s| s.kind == ProbeKind::Icmpv6Ra)
                .unwrap()
                .timeout_ms,
            5_000
        );
        let short = capture_quad(&default_plan(2_000));
        assert_eq!(
            short
                .iter()
                .find(|s| s.kind == ProbeKind::Icmpv6Ra)
                .unwrap()
                .timeout_ms,
            2_000
        );
    }

    #[test]
    fn dhcp_and_tftp_budgets_follow_passive_timeout() {
        // review round 1: the Python call site passes passive_timeout
        // to BOTH probes — the 30s in their signatures is a default
        // probe_router never uses
        let captures = capture_quad(&default_plan(10_000));
        for kind in [ProbeKind::Dhcp, ProbeKind::Tftp] {
            assert_eq!(
                captures.iter().find(|s| s.kind == kind).unwrap().timeout_ms,
                10_000,
                "{kind:?} must use the passive timeout"
            );
        }
        let custom = capture_quad(&default_plan(45_000));
        assert_eq!(
            custom
                .iter()
                .find(|s| s.kind == ProbeKind::Dhcp)
                .unwrap()
                .timeout_ms,
            45_000
        );
    }
}
