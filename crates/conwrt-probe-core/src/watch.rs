//! Time-series dark-target classification — the discriminator that
//! point-in-time probing cannot do.
//!
//! Born from the 2026-10-23 NR7101 incident: a router that wedged mid-boot
//! produced brief TCP-refused windows on the wire, then silence. To one-shot
//! probes, a boot loop, a hung boot, and a dead NIC all look identical.
//! Watching emission *windows* over time separates them:
//!
//! - [`WatchVerdict::SteadyUp`] — target answered within the last interval.
//! - [`WatchVerdict::BootLoop`] — emission windows recur with a stable
//!   period; the period estimates how far boot gets before the wedge, and
//!   every cycle re-opens the bootloader/failsafe windows.
//! - [`WatchVerdict::HungAfterBoot`] — life was seen, then silence for far
//!   longer than any plausible cycle: each power-on gives exactly ONE
//!   failsafe/Z-Loader window.
//! - [`WatchVerdict::Silent`] — no events on a *proven* capture path:
//!   L2-dead or hung before the network stack; watching across a power
//!   cycle discriminates.
//! - [`WatchVerdict::Inconclusive`] — no events and the capture path was
//!   never proven (no foreign traffic, no successful probe): silence is not
//!   evidence (dark-device doctrine: no negative without a positive
//!   control).
//!
//! Pure logic: no I/O here — probes and capture live in the CLI layer; this
//! module is fully unit-testable on synthetic timelines.

/// Emission gap that separates two windows, in seconds.
const QUIET_GAP_S: f64 = 10.0;
/// Silence (after life was seen) beyond which the target is verdict-hung.
const HUNG_SILENCE_S: f64 = 60.0;

/// What the target did at a point in time. Everything except `Passive` is
/// an answer to one of our own probes; `Passive` is the target talking
/// unprompted (ARP/DHCP/RA/beacons — the loudest dark-device signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Any L2/L3 frame from the target (passive capture).
    Passive,
    /// TCP connect completed (a service answered).
    TcpOpen,
    /// TCP connect refused — a kernel IP stack answered with RST.
    TcpRefused,
    /// ICMP echo reply.
    PingOk,
}

/// One timestamped emission.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WatchEvent {
    /// Seconds since watch start.
    pub t: f64,
    /// What happened.
    pub kind: EventKind,
}

/// Time-series verdict for the watched target.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WatchVerdict {
    /// Answered within the last quiet-gap window — not dark.
    SteadyUp,
    /// Emission windows recur: a watchdog/panic cycle. The period estimates
    /// how far boot gets before the wedge; every cycle re-opens the
    /// bootloader/failsafe windows.
    BootLoop {
        /// Median seconds between window starts.
        period_s: f64,
        /// Number of emission windows observed.
        windows: usize,
    },
    /// Life was seen, then silence far longer than any plausible cycle:
    /// the boot hangs; each power-on gives exactly ONE failsafe/Z-Loader window.
    HungAfterBoot {
        /// Seconds of silence since the last emission.
        silence_s: f64,
    },
    /// No events on a proven capture path: L2-dead or hung before the
    /// network stack; watching across a power cycle discriminates.
    Silent,
    /// No events and the capture path was never proven — silence is not
    /// evidence (no negative without a positive control).
    Inconclusive,
}

fn window_starts(events: &[WatchEvent]) -> Vec<f64> {
    let mut starts = Vec::new();
    let mut last: Option<f64> = None;
    for e in events {
        match last {
            None => starts.push(e.t),
            Some(prev) if e.t - prev > QUIET_GAP_S => starts.push(e.t),
            _ => {}
        }
        last = Some(e.t);
    }
    starts
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Classify a watch timeline. `control_ok` says whether the observation path
/// itself was proven (foreign traffic RECEIVED, or any probe ever answered).
/// Events may arrive out of order (passive capture vs probe rounds); the
/// timeline is sorted before clustering, so callers cannot corrupt the
/// window analysis by appending late.
pub fn classify(events: &[WatchEvent], watch_s: f64, control_ok: bool) -> WatchVerdict {
    let mut sorted: Vec<WatchEvent> = events.to_vec();
    sorted.sort_by(|a, b| a.t.partial_cmp(&b.t).unwrap());
    let events = &sorted[..];
    if events.is_empty() {
        return if control_ok {
            WatchVerdict::Silent
        } else {
            WatchVerdict::Inconclusive
        };
    }
    let last = events.iter().map(|e| e.t).fold(f64::MIN, f64::max);
    let silence = watch_s - last;
    if silence <= QUIET_GAP_S {
        return WatchVerdict::SteadyUp;
    }
    let starts = window_starts(events);
    if starts.len() >= 3 {
        // Recurring life is a cycle even when irregular; the median period
        // still tells you how far boot gets before the wedge.
        let mut periods: Vec<f64> = starts.windows(2).map(|w| w[1] - w[0]).collect();
        let period = median(&mut periods);
        return WatchVerdict::BootLoop {
            period_s: period,
            windows: starts.len(),
        };
    }
    if silence > HUNG_SILENCE_S {
        WatchVerdict::HungAfterBoot { silence_s: silence }
    } else {
        WatchVerdict::SteadyUp
    }
}

/// Human recovery guidance per verdict.
pub fn recovery_hint(v: &WatchVerdict) -> String {
    match v {
        WatchVerdict::SteadyUp => "target is alive; use point-in-time probes".into(),
        WatchVerdict::BootLoop { period_s, .. } => format!(
            "cycle ~{period_s:.0}s: watchdog/panic loop; failsafe window recurs every cycle \
             (hold button through power-on), zycast sender catches a window on any cycle"
        ),
        WatchVerdict::HungAfterBoot { .. } => {
            "ONE window per power-on: failsafe (button held through power-on) or start the \
             zycast sender BEFORE the next power-on"
                .into()
        }
        WatchVerdict::Silent => {
            "L2-dead or hung before the network stack: re-run this watch ACROSS a power \
             cycle — emissions that stop = hung; none ever = serial-gated"
                .into()
        }
        WatchVerdict::Inconclusive => {
            "capture path unproven — do not trust the silence; verify foreign traffic is \
             visible on the interface (positive control) and retry"
                .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(t: f64, k: EventKind) -> WatchEvent {
        WatchEvent { t, kind: k }
    }

    #[test]
    fn empty_with_control_is_silent() {
        assert_eq!(classify(&[], 120.0, true), WatchVerdict::Silent);
    }

    #[test]
    fn empty_without_control_is_inconclusive() {
        assert_eq!(classify(&[], 120.0, false), WatchVerdict::Inconclusive);
    }

    #[test]
    fn recent_answers_are_steady() {
        let evs = [ev(1.0, EventKind::PingOk), ev(118.0, EventKind::TcpRefused)];
        assert_eq!(classify(&evs, 120.0, true), WatchVerdict::SteadyUp);
    }

    #[test]
    fn one_window_then_long_silence_is_hung() {
        let evs = [
            ev(5.0, EventKind::TcpRefused),
            ev(7.0, EventKind::TcpRefused),
        ];
        match classify(&evs, 300.0, true) {
            WatchVerdict::HungAfterBoot { silence_s } => assert!((silence_s - 293.0).abs() < 1.0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unsorted_timelines_classify_as_if_sorted() {
        // The recurring_windows fixture, scrambled: passive arrival times
        // interleave with round-start timestamps of active probes, so the
        // append order from the CLI is NOT chronological.
        let mut evs = Vec::new();
        for w in 0..5 {
            evs.push(ev(w as f64 * 90.0, EventKind::Passive));
            evs.push(ev(w as f64 * 90.0 + 4.0, EventKind::TcpRefused));
        }
        let mut scrambled = evs.clone();
        scrambled.reverse();
        scrambled.swap(0, 3);
        scrambled.push(scrambled[1]);
        assert_ne!(scrambled, evs, "fixture must actually be unsorted");
        match classify(&scrambled, 500.0, true) {
            WatchVerdict::BootLoop { period_s, windows } => {
                assert_eq!(windows, 5);
                assert!((period_s - 90.0).abs() < 1.0);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn recurring_windows_are_a_loop() {
        let mut evs = Vec::new();
        for w in 0..5 {
            evs.push(ev(w as f64 * 90.0, EventKind::Passive));
            evs.push(ev(w as f64 * 90.0 + 4.0, EventKind::TcpRefused));
        }
        match classify(&evs, 500.0, true) {
            WatchVerdict::BootLoop { period_s, windows } => {
                assert_eq!(windows, 5);
                assert!((period_s - 90.0).abs() < 1.0);
            }
            other => panic!("{other:?}"),
        }
    }
}
