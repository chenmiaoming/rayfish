//! Who may use the connect channel (`ray connect` requests and invitations).
//!
//! Every decision uses the dialer's authenticated endpoint id, never a claim
//! inside a message: a request's `from_identity` is display only. A refused
//! dialer is closed without a reply, so it cannot tell a block from an
//! offline node.

use super::connect_service::PendingConnect;
use super::*;
use crate::config::InboundPolicy;

/// Pending connect requests strangers may hold together. A stranger beyond it
/// evicts the oldest stranger, never a known peer.
pub(crate) const MAX_STRANGER_CONNECTS: usize = 16;

/// How the connect channel treats a dialer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inbound {
    Blocked,
    /// Shares a network with this node, or is its paired primary.
    Known,
    Stranger,
}

/// Classify `remote`, the authenticated endpoint of the dialer.
pub(crate) fn classify(
    registry: &NetworkRegistry,
    config: &AppConfig,
    remote: EndpointId,
) -> Inbound {
    if config.blocked.contains(&remote) {
        Inbound::Blocked
    } else if registry.is_known(remote) {
        Inbound::Known
    } else {
        Inbound::Stranger
    }
}

/// Whether `policy` lets a dialer of this class through at all.
pub(crate) fn admits(policy: InboundPolicy, class: Inbound) -> bool {
    match class {
        Inbound::Blocked => false,
        Inbound::Known => policy != InboundPolicy::Nobody,
        Inbound::Stranger => policy == InboundPolicy::Anyone,
    }
}

/// Make room for a stranger's connect request: once strangers hold `cap`
/// entries, drop the oldest stranger and return its id. Known requesters are
/// never evicted, and a stranger re-dialing keeps its own slot.
pub(crate) fn evict_oldest_stranger(
    pending: &DashMap<EndpointId, PendingConnect>,
    incoming: EndpointId,
    cap: usize,
) -> Option<EndpointId> {
    if pending.contains_key(&incoming) {
        return None;
    }
    let strangers = pending.iter().filter(|e| e.value().stranger).count();
    if strangers < cap {
        return None;
    }
    let oldest = pending
        .iter()
        .filter(|e| e.value().stranger)
        .min_by_key(|e| e.value().requested_at)
        .map(|e| *e.key())?;
    pending.remove(&oldest);
    Some(oldest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from([seed; 32]).public()
    }

    fn request(endpoint: EndpointId, stranger: bool, age_ms: u64) -> PendingConnect {
        PendingConnect {
            from_endpoint: endpoint,
            hostname: None,
            requested_at: Instant::now() - Duration::from_secs(60) + Duration::from_millis(age_ms),
            stranger,
        }
    }

    #[test]
    fn policy_admission_table() {
        use InboundPolicy::*;
        let table = [
            (Anyone, Inbound::Blocked, false),
            (Anyone, Inbound::Known, true),
            (Anyone, Inbound::Stranger, true),
            (Known, Inbound::Blocked, false),
            (Known, Inbound::Known, true),
            (Known, Inbound::Stranger, false),
            (Nobody, Inbound::Blocked, false),
            (Nobody, Inbound::Known, false),
            (Nobody, Inbound::Stranger, false),
        ];
        for (policy, class, expected) in table {
            assert_eq!(admits(policy, class), expected, "{policy:?} {class:?}");
        }
    }

    #[test]
    fn strangers_share_sixteen_slots_and_known_peers_are_not_evicted() {
        let pending = DashMap::new();
        pending.insert(id(200), request(id(200), false, 0));
        for seed in 0..MAX_STRANGER_CONNECTS as u8 {
            pending.insert(id(seed), request(id(seed), true, u64::from(seed) + 1));
        }
        // A re-dial keeps its slot and evicts nobody.
        assert_eq!(
            evict_oldest_stranger(&pending, id(3), MAX_STRANGER_CONNECTS),
            None
        );
        // A new stranger evicts the oldest stranger, not the older known peer.
        assert_eq!(
            evict_oldest_stranger(&pending, id(99), MAX_STRANGER_CONNECTS),
            Some(id(0))
        );
        assert!(pending.contains_key(&id(200)));
        assert_eq!(pending.len(), MAX_STRANGER_CONNECTS);
    }
}
