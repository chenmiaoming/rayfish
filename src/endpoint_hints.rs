//! Successful transport paths, bounded by age, peer count and paths per peer.
//! Untimestamped legacy hints are discarded during startup.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::stream::{self, BoxStream};
use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use ray_proto::ipc::UnixTimestampSecs;
use serde::{Deserialize, Deserializer, Serialize};

use crate::config;

const MAX_PEERS: usize = 64;
const MAX_PATHS_PER_PEER: usize = 8;
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// One identity-authenticated path and the last time it was usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointHint {
    pub(crate) peer: EndpointId,
    pub(crate) addr: TransportAddr,
    pub(crate) last_success: UnixTimestampSecs,
}

pub(crate) fn now() -> Result<UnixTimestampSecs> {
    Ok(UnixTimestampSecs::from_secs(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs(),
    ))
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<EndpointHint>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StoredHint {
        Current(EndpointHint),
        Legacy(EndpointAddr),
    }

    Ok(Vec::<StoredHint>::deserialize(deserializer)?
        .into_iter()
        .flat_map(|hint| match hint {
            StoredHint::Current(hint) => vec![hint],
            StoredHint::Legacy(addr) => addr
                .addrs
                .into_iter()
                .map(|path| EndpointHint {
                    peer: addr.id,
                    addr: path,
                    last_success: UnixTimestampSecs::from_secs(0),
                })
                .collect(),
        })
        .collect())
}

pub(crate) fn prune(hints: &mut Vec<EndpointHint>, now: UnixTimestampSecs) {
    hints.retain(|hint| {
        matches!(hint.addr, TransportAddr::Ip(_) | TransportAddr::Relay(_))
            && hint.last_success.as_secs() != 0
            && now
                .as_secs()
                .checked_sub(hint.last_success.as_secs())
                .is_some_and(|age| age < MAX_AGE.as_secs())
    });
    hints.sort_by_key(|hint| hint.last_success);
    let mut peers = HashMap::new();
    let mut paths = HashSet::new();
    // Keep the newest paths and peers. Do not let one peer crowd out the rest.
    hints.reverse();
    hints.retain(|hint| {
        if !peers.contains_key(&hint.peer) && peers.len() == MAX_PEERS {
            return false;
        }
        let count = peers.entry(hint.peer).or_insert(0);
        if *count == MAX_PATHS_PER_PEER || !paths.insert((hint.peer, hint.addr.clone())) {
            return false;
        }
        *count += 1;
        true
    });
    hints.reverse();
}

/// The live lookup filters expiry on every resolution, even on an idle daemon.
/// Writers serialize disk commits and publication; readers only lock metadata.
#[derive(Debug, Clone, Default)]
pub struct WarmLookup {
    hints: Arc<RwLock<Vec<EndpointHint>>>,
    updates: Arc<Mutex<()>>,
}

impl WarmLookup {
    pub(crate) fn from_hints(mut hints: Vec<EndpointHint>) -> Result<Self> {
        prune(&mut hints, now()?);
        Ok(Self {
            hints: Arc::new(RwLock::new(hints)),
            ..Self::default()
        })
    }

    pub(crate) fn snapshot(&self, now: UnixTimestampSecs) -> Vec<EndpointHint> {
        let mut hints = self.hints.read().unwrap_or_else(|e| e.into_inner()).clone();
        prune(&mut hints, now);
        hints
    }

    pub(crate) fn update(
        &self,
        update: impl FnOnce(&mut Vec<EndpointHint>, UnixTimestampSecs),
    ) -> Result<()> {
        let _guard = self.updates.lock().unwrap_or_else(|e| e.into_inner());
        let now = now()?;
        let saved = config::update_settings(|cfg| {
            update(&mut cfg.endpoint_hints, now);
            prune(&mut cfg.endpoint_hints, now);
            Ok(())
        })?;
        *self.hints.write().unwrap_or_else(|e| e.into_inner()) = saved.endpoint_hints;
        Ok(())
    }

    pub(crate) fn remember(&self, peer: EndpointId, addr: TransportAddr) -> Result<()> {
        self.update(|hints, now| {
            hints.retain(|hint| hint.peer != peer || hint.addr != addr);
            hints.push(EndpointHint {
                peer,
                addr,
                last_success: now,
            });
        })
    }

    pub(crate) fn forget(&self, peer: EndpointId) -> Result<()> {
        self.update(|hints, _| hints.retain(|hint| hint.peer != peer))
    }

    #[cfg(test)]
    pub(crate) fn add_endpoint_info(&self, addr: EndpointAddr) {
        let now = now().unwrap();
        let mut hints = self.hints.write().unwrap();
        hints.extend(addr.addrs.into_iter().map(|path| EndpointHint {
            peer: addr.id,
            addr: path,
            last_success: now,
        }));
        prune(&mut hints, now);
    }
}

impl AddressLookup for WarmLookup {
    fn resolve(&self, peer: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        let now = match now() {
            Ok(now) => now,
            Err(error) => {
                tracing::warn!(%error, "cannot determine endpoint hint age");
                return None;
            }
        };
        let hints: Vec<_> = self
            .snapshot(now)
            .into_iter()
            .rev()
            .filter(|hint| hint.peer == peer)
            .map(|hint| {
                Ok(Item::new(
                    EndpointAddr::from_parts(peer, [hint.addr]).into(),
                    "warm_endpoint_hints",
                    hint.last_success.as_secs().checked_mul(1_000_000),
                ))
            })
            .collect();
        if hints.is_empty() {
            None
        } else {
            Some(Box::pin(stream::iter(hints)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::ffi::OsString;
    use tempfile::TempDir;

    fn peer(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn hint(peer: EndpointId, port: u16, seconds: u64) -> EndpointHint {
        EndpointHint {
            peer,
            addr: TransportAddr::Ip(format!("192.0.2.1:{port}").parse().unwrap()),
            last_success: UnixTimestampSecs::from_secs(seconds),
        }
    }

    #[test]
    fn freshness_belongs_to_each_path() {
        let fresh = MAX_AGE.as_secs() + 100;
        let old = hint(peer(1), 1000, 100);
        let recent = hint(peer(1), 1001, fresh);
        let mut hints = vec![old, recent.clone()];
        prune(&mut hints, UnixTimestampSecs::from_secs(fresh));
        assert_eq!(hints, vec![recent]);
    }

    #[test]
    fn unknown_and_future_ages_are_not_fresh() {
        let mut hints = vec![hint(peer(1), 1000, 0), hint(peer(1), 1001, 101)];
        prune(&mut hints, UnixTimestampSecs::from_secs(100));
        assert!(hints.is_empty());
    }

    #[test]
    fn address_churn_keeps_only_the_newest_paths() {
        let mut hints: Vec<_> = (1..=20).map(|n| hint(peer(1), n, u64::from(n))).collect();
        // An old copy of an address must not displace its more recent success.
        hints.push(hint(peer(1), 20, 1));
        prune(&mut hints, UnixTimestampSecs::from_secs(20));
        assert_eq!(hints.len(), MAX_PATHS_PER_PEER);
        assert_eq!(hints.first().unwrap().last_success.as_secs(), 13);
        assert_eq!(hints.last().unwrap().last_success.as_secs(), 20);
    }

    #[test]
    fn peer_eviction_keeps_the_newest_peers() {
        let mut hints: Vec<_> = (1..=65)
            .map(|n| hint(peer(n), 1000, u64::from(n)))
            .collect();
        prune(&mut hints, UnixTimestampSecs::from_secs(65));
        assert_eq!(hints.len(), MAX_PEERS);
        assert!(hints.iter().all(|hint| hint.peer != peer(1)));
    }

    #[tokio::test]
    async fn recent_relays_remain_fallbacks_alongside_direct_paths() {
        use futures::StreamExt;

        let mut relay = hint(peer(1), 1000, now().unwrap().as_secs());
        relay.addr = TransportAddr::Relay("https://relay.example.com".parse().unwrap());
        let direct = hint(peer(1), 1001, relay.last_success.as_secs());
        let lookup = WarmLookup::from_hints(vec![relay.clone(), direct.clone()]).unwrap();
        let items: Vec<_> = lookup.resolve(peer(1)).unwrap().collect().await;
        let addresses: Vec<_> = items
            .into_iter()
            .flat_map(|item| {
                item.unwrap()
                    .endpoint_info()
                    .clone()
                    .into_endpoint_addr()
                    .addrs
            })
            .collect();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&relay.addr));
        assert!(addresses.contains(&direct.addr));
    }

    #[test]
    fn expiry_applies_without_a_restart_or_another_connection() {
        let hint = hint(peer(1), 1000, 100);
        let lookup = WarmLookup::default();
        *lookup.hints.write().unwrap() = vec![hint];
        assert_eq!(lookup.snapshot(UnixTimestampSecs::from_secs(101)).len(), 1);
        assert!(
            lookup
                .snapshot(UnixTimestampSecs::from_secs(100 + MAX_AGE.as_secs()))
                .is_empty()
        );
        assert!(lookup.resolve(peer(1)).is_none());
    }

    struct TestConfig {
        directory: TempDir,
        previous: Option<OsString>,
    }

    impl TestConfig {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
            // SAFETY: callers hold CONFIG_ENV_LOCK until this guard is dropped.
            unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", directory.path()) };
            Self {
                directory,
                previous,
            }
        }
    }

    impl Drop for TestConfig {
        fn drop(&mut self) {
            // SAFETY: callers still hold CONFIG_ENV_LOCK.
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                    None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
                }
            }
        }
    }

    #[test]
    fn persistence_and_live_lookup_share_limits_and_peer_scoped_reset() {
        let _lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _config = TestConfig::new();
        let lookup = WarmLookup::default();
        let timestamp = now().unwrap();
        lookup
            .update(|hints, _| {
                hints.extend((1..=65).map(|seed| hint(peer(seed), 1000, timestamp.as_secs())));
            })
            .unwrap();
        assert!(lookup.resolve(peer(1)).is_none());
        assert_eq!(
            lookup.snapshot(now().unwrap()),
            config::load().unwrap().endpoint_hints
        );

        for port in 1001..1020 {
            lookup
                .remember(peer(65), hint(peer(65), port, 1).addr)
                .unwrap();
        }
        assert_eq!(
            lookup
                .snapshot(now().unwrap())
                .iter()
                .filter(|hint| hint.peer == peer(65))
                .count(),
            MAX_PATHS_PER_PEER
        );
        assert_eq!(
            lookup.snapshot(now().unwrap()),
            config::load().unwrap().endpoint_hints
        );

        lookup.forget(peer(65)).unwrap();
        assert!(lookup.resolve(peer(65)).is_none());
        assert!(lookup.resolve(peer(64)).is_some());
        let reloaded = WarmLookup::from_hints(config::load().unwrap().endpoint_hints).unwrap();
        assert!(reloaded.resolve(peer(65)).is_none());
        assert!(reloaded.resolve(peer(64)).is_some());
    }

    #[test]
    fn failed_persistence_keeps_the_live_lookup_unchanged() {
        let _lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let config = TestConfig::new();
        let fresh = hint(peer(1), 1000, now().unwrap().as_secs());
        let lookup = WarmLookup::from_hints(vec![fresh.clone()]).unwrap();
        std::fs::write(config.directory.path().join("settings.toml"), "invalid = [").unwrap();
        assert!(lookup.forget(peer(1)).is_err());
        assert_eq!(lookup.snapshot(now().unwrap()), vec![fresh]);
    }

    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn daemon_inspection_and_reset_survive_restart() {
        use crate::daemon::{PeerIdentity, build_headless};
        use crate::ipc::IpcMessage;

        let _lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _config = TestConfig::new();
        let timestamp = now().unwrap().as_secs();
        let fresh = hint(peer(1), 1001, timestamp);
        config::update_settings(|cfg| {
            cfg.mdns_enabled = false;
            cfg.dns_mode = config::DnsMode::Off;
            cfg.endpoint_hints = vec![
                hint(peer(1), 1000, timestamp - MAX_AGE.as_secs()),
                fresh.clone(),
                hint(peer(2), 1002, timestamp),
            ];
            Ok(())
        })
        .unwrap();
        let daemon = build_headless(true).await.unwrap();
        assert_eq!(config::load().unwrap().endpoint_hints.len(), 2);
        let request = |reset| IpcMessage::EndpointHints {
            peer: peer(1).to_string(),
            reset,
        };
        let response = daemon.handle_request(request(false), None, vec![]).await;
        let IpcMessage::EndpointHintsList { peer: id, hints } = response else {
            panic!("expected cached endpoint hints");
        };
        assert_eq!(id, peer(1));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].address, fresh.addr);
        assert_eq!(hints[0].last_success, fresh.last_success);
        assert!(matches!(
            daemon.handle_request(request(true), None, vec![]).await,
            IpcMessage::Error { .. }
        ));
        let root = Some(PeerIdentity::Unix { uid: 0, gid: 0 });
        assert!(matches!(
            daemon.handle_request(request(true), root, vec![]).await,
            IpcMessage::Ok { .. }
        ));
        let response = daemon.handle_request(request(false), None, vec![]).await;
        assert!(
            matches!(response, IpcMessage::EndpointHintsList { hints, .. } if hints.is_empty())
        );
        assert_eq!(config::load().unwrap().endpoint_hints.len(), 1);
        daemon.shutdown_and_close().await;

        let daemon = build_headless(true).await.unwrap();
        let response = daemon.handle_request(request(false), None, vec![]).await;
        assert!(
            matches!(response, IpcMessage::EndpointHintsList { hints, .. } if hints.is_empty())
        );
        daemon.shutdown_and_close().await;
    }
}
