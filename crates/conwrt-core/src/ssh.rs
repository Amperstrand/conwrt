//! SSH host-key trust ladder — engine-level safety policy (ADR-0005),
//! reimplemented as a pure decision function over presented keys, explicit
//! pins, and a persistent store (the pattern absorbed from the TollGate
//! installer's model, which itself encodes three real MITM/false-refusal
//! incidents).
//!
//! Rules, evaluated in order:
//! 1. **Pin wins**: an explicit per-operation fingerprint pin that matches
//!    the presented key trusts immediately; a mismatch always refuses.
//! 2. **Store match**: a stored entry with the same fingerprint trusts.
//! 3. **Changed key under the same algorithm refuses** — the classic
//!    MITM/reimage signature. Not auto-updatable.
//! 4. **Different key *type* is a distinct case**: Dropbear servers serve
//!    one host key per algorithm, so an algorithm switch (e.g. a client
//!    that previously saw ed25519 now negotiating RSA) presents a
//!    legitimately different key. This still refuses, but with a reason
//!    that tells the operator re-trusting may be appropriate.
//! 5. **Unknown host**: `TrustOnFirstUse` trusts and asks the caller to
//!    remember; `Strict` refuses with the exact pin command to use.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What the remote end presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyView {
    /// SSH public-key algorithm name (`ssh-ed25519`, `rsa-sha2-256`, ...).
    pub key_algo: String,
    /// OpenSSH-format fingerprint (`SHA256:<base64, no padding>`).
    pub fingerprint: String,
}

/// Whether unknown hosts may be trusted on first use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Refuse anything not pinned or stored (scripted/production flows).
    Strict,
    /// Interactive first-use: trust and remember (the operator is assumed
    /// to be watching).
    TrustOnFirstUse,
}

/// Why a key was trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedHow {
    /// Matched the explicit per-operation pin.
    Pinned,
    /// Matched a previously stored key.
    Stored,
    /// First use under TOFU mode (caller should remember the key).
    FirstUse,
}

/// Why a key was refused (refusal-as-data: the UI/CLI renders this, the
/// engine never strings-matches error text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The key that was presented.
    pub presented: HostKeyView,
    /// Machine-readable reason.
    pub reason: RefusalReason,
    /// Operator-facing remediation (includes the pin command).
    pub hint: String,
}

/// Refusal taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// Presented key differs from the explicit pin.
    PinMismatch,
    /// Same algorithm as a stored key, different key — MITM/reimage
    /// signature.
    ChangedKey,
    /// No stored key uses this algorithm; Dropbear serves one key per
    /// algorithm, so this may be legitimate (client-side algorithm
    /// negotiation changed) — re-trust explicitly if expected.
    CrossKeyType {
        /// Algorithms already stored for this host.
        stored_algos: Vec<String>,
    },
    /// Host unknown and mode is [`TrustMode::Strict`].
    FirstUse,
}

/// The ladder verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Proceed; caller remembers the key when [`TrustedHow::FirstUse`].
    Trusted(TrustedHow),
    /// Stop before any credential is sent.
    Refused(Refusal),
}

/// Evaluate the trust ladder for one presented host key.
///
/// `stored` is the store's entry list for this host (empty = unknown).
#[must_use]
pub fn evaluate_host_key(
    host: &str,
    presented: &HostKeyView,
    pin: Option<&str>,
    stored: &[HostKeyView],
    mode: TrustMode,
) -> TrustDecision {
    if let Some(pin) = pin {
        if presented.fingerprint == pin {
            return TrustDecision::Trusted(TrustedHow::Pinned);
        }
        return TrustDecision::Refused(Refusal {
            presented: presented.clone(),
            reason: RefusalReason::PinMismatch,
            hint: pin_hint(host, &presented.fingerprint),
        });
    }

    if stored.is_empty() {
        return match mode {
            TrustMode::TrustOnFirstUse => TrustDecision::Trusted(TrustedHow::FirstUse),
            TrustMode::Strict => TrustDecision::Refused(Refusal {
                presented: presented.clone(),
                reason: RefusalReason::FirstUse,
                hint: pin_hint(host, &presented.fingerprint),
            }),
        };
    }

    if stored
        .iter()
        .any(|entry| entry.fingerprint == presented.fingerprint)
    {
        return TrustDecision::Trusted(TrustedHow::Stored);
    }

    let same_algo_different_key = stored
        .iter()
        .any(|entry| entry.key_algo == presented.key_algo);
    if same_algo_different_key {
        return TrustDecision::Refused(Refusal {
            presented: presented.clone(),
            reason: RefusalReason::ChangedKey,
            hint: format!(
                "host {host} key changed ({}): verify out-of-band before re-trusting; {}",
                presented.key_algo,
                pin_command(&presented.fingerprint)
            ),
        });
    }

    let stored_algos = stored.iter().map(|e| e.key_algo.clone()).collect();
    TrustDecision::Refused(Refusal {
        presented: presented.clone(),
        reason: RefusalReason::CrossKeyType { stored_algos },
        hint: format!(
            "host {host} presented a {} key but stored keys use other algorithms \
             (Dropbear serves one key per algorithm — may be legitimate); {}",
            presented.key_algo,
            pin_command(&presented.fingerprint)
        ),
    })
}

fn pin_command(fingerprint: &str) -> String {
    format!("re-run with --trust-host-key {fingerprint}")
}

impl core::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RefusalReason::PinMismatch => write!(f, "pin mismatch"),
            RefusalReason::ChangedKey => write!(f, "host key changed"),
            RefusalReason::CrossKeyType { stored_algos } => {
                write!(f, "key type changed (stored: {stored_algos:?})")
            }
            RefusalReason::FirstUse => write!(f, "unknown host"),
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "host key refused ({}): {}; {}",
            self.reason, self.presented.fingerprint, self.hint
        )
    }
}

fn pin_hint(host: &str, fingerprint: &str) -> String {
    format!(
        "host key for {host} is not trusted; verify the fingerprint out-of-band, then {}",
        pin_command(fingerprint)
    )
}

/// An in-memory [`TrustStore`] for tests and single-session TOFU flows.
#[derive(Debug, Default, Clone)]
pub struct MemoryTrustStore {
    entries: Vec<(String, HostKeyView)>,
}

impl MemoryTrustStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store entries known for `host`.
    #[must_use]
    pub fn entries(&self, host: &str) -> Vec<HostKeyView> {
        self.entries
            .iter()
            .filter(|(h, _)| h == host)
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// Remember a key for `host` (deduplicated).
    pub fn remember(&mut self, host: &str, key: &HostKeyView) {
        if !self.entries.iter().any(|(h, k)| h == host && *k == *key) {
            self.entries.push((host.to_string(), key.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ED2: &str = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RSA: &str = "SHA256:ccccccccccccccccccccccccccccccccccccccccccc";

    fn ed_key(fp: &str) -> HostKeyView {
        HostKeyView {
            key_algo: "ssh-ed25519".into(),
            fingerprint: fp.into(),
        }
    }

    fn rsa_key(fp: &str) -> HostKeyView {
        HostKeyView {
            key_algo: "rsa-sha2-256".into(),
            fingerprint: fp.into(),
        }
    }

    #[test]
    fn matching_pin_trusts() {
        let d = evaluate_host_key("h", &ed_key(ED), Some(ED), &[], TrustMode::Strict);
        assert_eq!(d, TrustDecision::Trusted(TrustedHow::Pinned));
    }

    #[test]
    fn pin_mismatch_refuses_even_with_matching_store() {
        let d = evaluate_host_key(
            "h",
            &ed_key(ED2),
            Some(ED),
            &[ed_key(ED2)],
            TrustMode::TrustOnFirstUse,
        );
        assert!(
            matches!(d, TrustDecision::Refused(ref r) if r.reason == RefusalReason::PinMismatch)
        );
    }

    #[test]
    fn stored_match_trusts() {
        let d = evaluate_host_key("h", &ed_key(ED), None, &[ed_key(ED)], TrustMode::Strict);
        assert_eq!(d, TrustDecision::Trusted(TrustedHow::Stored));
    }

    #[test]
    fn strict_first_use_refuses_with_pin_command() {
        let d = evaluate_host_key("h", &ed_key(ED), None, &[], TrustMode::Strict);
        match d {
            TrustDecision::Refused(r) => {
                assert_eq!(r.reason, RefusalReason::FirstUse);
                assert!(r.hint.contains("--trust-host-key SHA256:"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn tofu_first_use_trusts() {
        let d = evaluate_host_key("h", &ed_key(ED), None, &[], TrustMode::TrustOnFirstUse);
        assert_eq!(d, TrustDecision::Trusted(TrustedHow::FirstUse));
    }

    #[test]
    fn changed_key_same_algo_refuses() {
        let d = evaluate_host_key(
            "h",
            &ed_key(ED2),
            None,
            &[ed_key(ED)],
            TrustMode::TrustOnFirstUse,
        );
        match d {
            TrustDecision::Refused(r) => {
                assert_eq!(r.reason, RefusalReason::ChangedKey);
                assert!(r.hint.contains("key changed"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn different_algo_is_cross_key_type_not_changed_key() {
        let d = evaluate_host_key(
            "h",
            &rsa_key(RSA),
            None,
            &[ed_key(ED)],
            TrustMode::TrustOnFirstUse,
        );
        match d {
            TrustDecision::Refused(r) => {
                assert_eq!(
                    r.reason,
                    RefusalReason::CrossKeyType {
                        stored_algos: vec!["ssh-ed25519".into()]
                    }
                );
                assert!(r.hint.contains("one key per algorithm"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn store_remember_dedupes() {
        let mut store = MemoryTrustStore::new();
        store.remember("h", &ed_key(ED));
        store.remember("h", &ed_key(ED));
        store.remember("other", &ed_key(ED));
        assert_eq!(store.entries("h").len(), 1);
        assert_eq!(store.entries("other").len(), 1);
        assert!(store.entries("missing").is_empty());
    }
}
