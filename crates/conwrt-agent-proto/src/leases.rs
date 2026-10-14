//! The agent-side lease table (issue #108): exclusive/shared resource
//! leases with heartbeat expiry and controller-disconnect policies, per
//! ADR-0004 §5.
//!
//! Pure state machine — no I/O, no clock. The embedder drives time via
//! [`LeaseTable::tick`] (call it at the granted heartbeat interval) and
//! feeds disconnect events explicitly. This keeps the table testable and
//! MCU-portable (ADR-0002: time is a capability, not a global).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::protocol::{DisconnectPolicy, LeaseExpired, LeaseExpiryReason};

/// One held lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Lease id (agent-assigned, monotonically increasing).
    pub id: u64,
    /// Resource name.
    pub resource: String,
    /// Owning controller identity.
    pub controller: String,
    /// Exclusive or shared.
    pub exclusive: bool,
    /// Disconnect policy for work under this lease.
    pub on_disconnect: DisconnectPolicy,
    /// Heartbeats remaining before expiry (decremented per tick).
    pub heartbeat_budget: u32,
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDenied {
    /// Another controller holds it exclusively.
    HeldBy(String),
    /// This controller already holds it (re-acquire not supported).
    AlreadyHeld,
}

/// Errors from lease operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// Unknown lease id.
    UnknownLease(u64),
    /// A refusal with the reason.
    Denied(LeaseDenied),
}

/// The table. `next_id` hands out lease ids; `leases` is keyed by id.
#[derive(Debug, Default)]
pub struct LeaseTable {
    next_id: u64,
    leases: BTreeMap<u64, Lease>,
}

impl LeaseTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to grant a lease; returns the lease id.
    ///
    /// `heartbeat_budget` = how many missed heartbeats expire the lease
    /// (granted as `budget = 3 × interval` by the caller, e.g.).
    pub fn acquire(
        &mut self,
        resource: &str,
        controller: &str,
        exclusive: bool,
        on_disconnect: DisconnectPolicy,
        heartbeat_budget: u32,
    ) -> Result<u64, LeaseError> {
        for lease in self.leases.values() {
            if lease.resource == resource && lease.controller == controller {
                return Err(LeaseError::Denied(LeaseDenied::AlreadyHeld));
            }
            if lease.resource == resource && (lease.exclusive || exclusive) {
                return Err(LeaseError::Denied(LeaseDenied::HeldBy(
                    lease.controller.clone(),
                )));
            }
        }
        self.next_id += 1;
        let id = self.next_id;
        self.leases.insert(
            id,
            Lease {
                id,
                resource: String::from(resource),
                controller: String::from(controller),
                exclusive,
                on_disconnect,
                heartbeat_budget,
            },
        );
        Ok(id)
    }

    /// Record a heartbeat: refills the budget.
    pub fn heartbeat(&mut self, lease_id: u64, refill_to: u32) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(&lease_id)
            .ok_or(LeaseError::UnknownLease(lease_id))?;
        lease.heartbeat_budget = refill_to;
        Ok(())
    }

    /// Release a lease (controller-initiated).
    pub fn release(&mut self, lease_id: u64) -> Result<Lease, LeaseError> {
        self.leases
            .remove(&lease_id)
            .ok_or(LeaseError::UnknownLease(lease_id))
    }

    /// Advance one heartbeat interval: decrement budgets, expire dead
    /// leases. Returns the expiry events (with reasons) for the agent to
    /// publish.
    #[must_use]
    pub fn tick(&mut self) -> Vec<LeaseExpired> {
        let mut expired = Vec::new();
        let dead: Vec<u64> = self
            .leases
            .iter_mut()
            .filter_map(|(id, lease)| {
                lease.heartbeat_budget = lease.heartbeat_budget.saturating_sub(1);
                (lease.heartbeat_budget == 0).then_some(*id)
            })
            .collect();
        for id in dead {
            if self.leases.remove(&id).is_some() {
                expired.push(LeaseExpired {
                    lease_id: id,
                    reason: LeaseExpiryReason::HeartbeatTimeout,
                });
            }
        }
        expired
    }

    /// All live leases (for capability/status reporting).
    pub fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values()
    }

    /// Look up one lease.
    pub fn get(&self, lease_id: u64) -> Option<&Lease> {
        self.leases.get(&lease_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_grants_and_ids_increment() {
        let mut t = LeaseTable::new();
        let a = t
            .acquire("uart0", "laptop", true, DisconnectPolicy::Abort, 3)
            .unwrap();
        let b = t
            .acquire("eth0", "laptop", false, DisconnectPolicy::Complete, 3)
            .unwrap();
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    #[test]
    fn exclusive_conflicts_refuse_with_holder() {
        let mut t = LeaseTable::new();
        t.acquire("uart0", "laptop-a", true, DisconnectPolicy::Abort, 3)
            .unwrap();
        match t.acquire("uart0", "laptop-b", true, DisconnectPolicy::Abort, 3) {
            Err(LeaseError::Denied(LeaseDenied::HeldBy(h))) => assert_eq!(h, "laptop-a"),
            other => panic!("expected HeldBy, got {other:?}"),
        }
    }

    #[test]
    fn shared_coexists_but_not_with_exclusive() {
        let mut t = LeaseTable::new();
        t.acquire("eth0", "a", false, DisconnectPolicy::Abort, 3)
            .unwrap();
        assert!(
            t.acquire("eth0", "b", false, DisconnectPolicy::Abort, 3)
                .is_ok()
        );
        let mut t2 = LeaseTable::new();
        t2.acquire("eth0", "a", true, DisconnectPolicy::Abort, 3)
            .unwrap();
        assert!(
            t2.acquire("eth0", "b", false, DisconnectPolicy::Abort, 3)
                .is_err()
        );
    }

    #[test]
    fn duplicate_acquire_by_same_controller_refused() {
        let mut t = LeaseTable::new();
        t.acquire("uart0", "a", true, DisconnectPolicy::Abort, 3)
            .unwrap();
        assert!(matches!(
            t.acquire("uart0", "a", true, DisconnectPolicy::Abort, 3),
            Err(LeaseError::Denied(LeaseDenied::AlreadyHeld))
        ));
    }

    #[test]
    fn heartbeat_refills_and_prevents_expiry() {
        let mut t = LeaseTable::new();
        let id = t
            .acquire("uart0", "a", true, DisconnectPolicy::Abort, 2)
            .unwrap();
        let _ = t.tick(); // budget 2→1
        assert!(t.get(id).is_some());
        t.heartbeat(id, 2).unwrap(); // refill
        let _ = t.tick(); // 2→1
        let _ = t.tick(); // 1→0 → expired
        assert!(t.get(id).is_none());
        assert!(matches!(
            t.heartbeat(id, 2),
            Err(LeaseError::UnknownLease(_))
        ));
    }

    #[test]
    fn tick_reports_expiry_events() {
        let mut t = LeaseTable::new();
        let id = t
            .acquire("pwr/bay3", "a", true, DisconnectPolicy::Complete, 1)
            .unwrap();
        let expired = t.tick();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, id);
    }

    #[test]
    fn release_frees_for_next_controller() {
        let mut t = LeaseTable::new();
        let id = t
            .acquire("uart0", "a", true, DisconnectPolicy::Abort, 9)
            .unwrap();
        t.release(id).unwrap();
        assert!(
            t.acquire("uart0", "b", true, DisconnectPolicy::Abort, 9)
                .is_ok()
        );
    }
}
