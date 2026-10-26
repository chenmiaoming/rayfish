//! Limits on concurrent mesh SSH connections.
//!
//! A slot is taken on accept, before authentication, so the limits have to
//! hold against peers that will never log in. A global cap alone lets one
//! source hold every slot through the login grace and reconnect, so each
//! source address also has its own, smaller cap. Mesh addresses are bound to
//! peer identities by the forwarding path's anti-spoof check.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type Counts = Arc<Mutex<HashMap<IpAddr, usize>>>;

pub(super) struct ConnectionSlots {
    total: Arc<Semaphore>,
    per_source: usize,
    counts: Counts,
}

/// One accepted connection's place; dropping it frees the place.
pub(super) struct ConnectionSlot {
    _total: OwnedSemaphorePermit,
    source: IpAddr,
    counts: Counts,
}

impl ConnectionSlots {
    pub(super) fn new(total: usize, per_source: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_source,
            counts: Arc::default(),
        }
    }

    /// A slot for a connection from `source`, or `None` when either that
    /// source or the server as a whole is at its limit.
    pub(super) fn try_acquire(&self, source: IpAddr) -> Option<ConnectionSlot> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(source).or_default();
        if *count >= self.per_source {
            return None;
        }
        let total = Arc::clone(&self.total).try_acquire_owned().ok()?;
        *count += 1;
        Some(ConnectionSlot {
            _total: total,
            source,
            counts: Arc::clone(&self.counts),
        })
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn ip(last: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, last))
    }

    #[test]
    fn one_source_cannot_take_every_slot() {
        let slots = ConnectionSlots::new(8, 2);
        let held: Vec<_> = (0..2).map(|_| slots.try_acquire(ip(1))).collect();
        assert!(held.iter().all(Option::is_some));
        assert!(slots.try_acquire(ip(1)).is_none(), "past the source cap");
        assert!(
            slots.try_acquire(ip(2)).is_some(),
            "another source still fits"
        );
    }

    #[test]
    fn the_total_cap_holds_across_sources() {
        let slots = ConnectionSlots::new(2, 2);
        let _a = slots.try_acquire(ip(1)).expect("first");
        let _b = slots.try_acquire(ip(2)).expect("second");
        assert!(slots.try_acquire(ip(3)).is_none(), "past the total cap");
    }

    #[test]
    fn a_closed_connection_frees_its_slot() {
        let slots = ConnectionSlots::new(8, 1);
        let held = slots.try_acquire(ip(1)).expect("first");
        assert!(slots.try_acquire(ip(1)).is_none());
        drop(held);
        assert!(slots.try_acquire(ip(1)).is_some(), "slot not returned");
        assert!(slots.counts.lock().expect("lock").len() <= 1);
    }
}
