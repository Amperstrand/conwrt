//! Probe scheduling — the pure, time-parameterized state machine under
//! `router-probe.py::probe_router`'s probe sequencing (and the ordered
//! gates of `scripts/flash/detect.py`).
//!
//! The Python flow is: instant passive probes (link, ARP), then
//! time-bounded capture probes (failsafe broadcast, ICMPv6 RA, DHCP,
//! TFTP), then active probes (HTTP GET/HEAD, ping, SSH, SSH failsafe),
//! then classification. Wall-clock parallelism there is an
//! optimization; the SEMANTICS are an ordered sequence where every
//! probe runs unconditionally, each bounded by its timeout. This
//! scheduler models exactly that: the caller owns the clock
//! (ADR-0002 — time is a capability) and performs the actual probe
//! I/O; the scheduler decides which probe is current and when its
//! budget has expired.

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

/// The probe kinds the source of truth runs, in `probe_router` order.
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
    /// `probe_dhcp` — bounded DHCP capture (30s).
    Dhcp,
    /// `probe_tftp` — bounded TFTP RRQ capture (30s).
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

/// What the scheduler wants the driver to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeEvent {
    /// Begin this probe now (its budget started at the poll instant).
    Start(ProbeKind),
    /// The current probe's budget expired — abandon it; the next poll
    /// starts the following probe (the Python future timeouts).
    TimedOut(ProbeKind),
    /// The current probe is still within its budget — keep driving it.
    Waiting(ProbeKind),
    /// Every step has run; proceed to classification.
    Complete,
}

/// Time-bounded sequential probe scheduler with an injected clock.
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
///     sched.finish_current();
/// }
/// ```
#[derive(Debug)]
pub struct ProbeScheduler {
    steps: Vec<ProbeStep>,
    next: usize,
    current: Option<(ProbeStep, u64)>, // (step, started_at)
}

impl ProbeScheduler {
    /// New scheduler over `steps`; the first [`Self::poll`] starts
    /// step 0. The plan drives ordering — see [`default_plan`] for the
    /// source-of-truth sequence and budgets.
    #[must_use]
    pub fn new(steps: Vec<ProbeStep>) -> Self {
        Self {
            steps,
            next: 0,
            current: None,
        }
    }

    /// Advance the machine at time `now_ms` (caller-injected clock).
    #[must_use]
    pub fn poll(&mut self, now_ms: u64) -> ProbeEvent {
        if let Some((step, started_at)) = self.current {
            if step.timeout_ms > 0 && now_ms.saturating_sub(started_at) >= step.timeout_ms {
                self.advance();
                return ProbeEvent::TimedOut(step.kind);
            }
            return ProbeEvent::Waiting(step.kind);
        }
        if self.next >= self.steps.len() {
            return ProbeEvent::Complete;
        }
        let step = self.steps[self.next];
        self.current = Some((step, now_ms));
        self.next += 1;
        ProbeEvent::Start(step.kind)
    }

    /// The driver reports the current probe concluded (answered or
    /// failed on its own — any result). No-op when nothing is current.
    pub fn finish_current(&mut self) {
        if self.current.is_some() {
            self.advance();
        }
    }

    fn advance(&mut self) {
        self.current = None;
    }
}

/// The `probe_router` plan: instant passive reads, bounded captures
/// (passive-timeout-driven), then active probes — Python's default
/// budgets (`passive_timeout` default 10s; DHCP/TFTP 30s; curl 3s;
/// ping 2s; SSH 8s).
#[must_use]
pub fn default_plan(passive_timeout_ms: u64) -> Vec<ProbeStep> {
    let ra_budget = passive_timeout_ms.min(5_000);
    vec![
        ProbeStep {
            kind: ProbeKind::LinkState,
            timeout_ms: 0,
        },
        ProbeStep {
            kind: ProbeKind::Arp,
            timeout_ms: 0,
        },
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
            timeout_ms: 30_000,
        },
        ProbeStep {
            kind: ProbeKind::Tftp,
            timeout_ms: 30_000,
        },
        ProbeStep {
            kind: ProbeKind::HttpGet,
            timeout_ms: 3_000,
        },
        ProbeStep {
            kind: ProbeKind::HttpHead,
            timeout_ms: 3_000,
        },
        ProbeStep {
            kind: ProbeKind::Ping,
            timeout_ms: 2_000,
        },
        ProbeStep {
            kind: ProbeKind::Ssh,
            timeout_ms: 8_000,
        },
        ProbeStep {
            kind: ProbeKind::SshFailsafe,
            timeout_ms: 8_000,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_starts_each_step_in_source_order() {
        let mut sched = ProbeScheduler::new(default_plan(10_000));
        let mut t = 1_000;
        let mut started = Vec::new();
        loop {
            match sched.poll(t) {
                ProbeEvent::Start(kind) => {
                    started.push(kind);
                    sched.finish_current(); // probes answer instantly here
                }
                ProbeEvent::Waiting(_) => panic!("instant finish never waits"),
                ProbeEvent::TimedOut(_) => panic!("instant finish never times out"),
                ProbeEvent::Complete => break,
            }
            t += 1;
        }
        assert_eq!(
            started,
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
    fn budget_expiry_times_out_and_moves_on() {
        let plan = vec![ProbeStep {
            kind: ProbeKind::Dhcp,
            timeout_ms: 30_000,
        }];
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
    fn finish_current_short_circuits_the_budget() {
        let plan = vec![
            ProbeStep {
                kind: ProbeKind::HttpGet,
                timeout_ms: 3_000,
            },
            ProbeStep {
                kind: ProbeKind::Ping,
                timeout_ms: 2_000,
            },
        ];
        let mut sched = ProbeScheduler::new(plan);
        assert_eq!(sched.poll(0), ProbeEvent::Start(ProbeKind::HttpGet));
        sched.finish_current(); // curl answered in 10ms
        assert_eq!(sched.poll(10), ProbeEvent::Start(ProbeKind::Ping));
        sched.finish_current();
        assert_eq!(sched.poll(11), ProbeEvent::Complete);
    }

    #[test]
    fn empty_plan_completes_immediately() {
        let mut sched = ProbeScheduler::new(Vec::new());
        assert_eq!(sched.poll(0), ProbeEvent::Complete);
    }

    #[test]
    fn ra_budget_is_capped_at_five_seconds() {
        let plan = default_plan(10_000);
        assert_eq!(
            plan.iter()
                .find(|s| s.kind == ProbeKind::Icmpv6Ra)
                .unwrap()
                .timeout_ms,
            5_000
        );
        let short = default_plan(2_000);
        assert_eq!(
            short
                .iter()
                .find(|s| s.kind == ProbeKind::Icmpv6Ra)
                .unwrap()
                .timeout_ms,
            2_000
        );
    }
}
