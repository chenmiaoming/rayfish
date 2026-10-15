//! A paired device asking its primary to revoke it, when it unpairs itself.
//!
//! Only the primary revokes a device network-wide: the nullifier rides the
//! signed blob, which only a network-key holder writes. A device that unpairs
//! itself therefore sends its primary `ControlMsg::RequestUnpair` before it
//! leaves its networks, and the request has to arrive although the device is
//! about to share no network with the primary:
//!
//! - With no link to the primary, the usual state between on-demand nodes, the
//!   primary is dialed for the request.
//! - With the primary unreachable, the request is saved
//!   (`AppConfig::pending_unpair_request`) and retried until the primary has
//!   received it. Nothing else brings the two together again: once the device
//!   has left, neither side has a reason to dial the other.
//! - A device that pairs again drops the saved request, which would otherwise
//!   revoke the new pairing.

use super::super::*;

/// How long unpairing waits for the primary to receive the request: a dial plus
/// its acknowledgement. Past it the request is saved and retried.
const UNPAIR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The first wait before retrying a saved request, doubled after each miss up
/// to [`UNPAIR_RETRY_MAX`]. A primary can stay offline for days, and the device
/// doing the retrying is usually a phone.
const UNPAIR_RETRY_MIN: Duration = Duration::from_secs(60);
const UNPAIR_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

impl NetworkRegistry {
    /// Ask `primary` to revoke this device, waiting at most
    /// [`UNPAIR_REQUEST_TIMEOUT`] until it has received the request. A request
    /// that does not get there is saved for [`Self::run_unpair_retries`].
    pub(crate) async fn request_unpair(&self, primary: EndpointId) {
        match tokio::time::timeout(UNPAIR_REQUEST_TIMEOUT, self.deliver_unpair_request(primary))
            .await
        {
            Ok(Ok(())) => return,
            Ok(Err(e)) => tracing::warn!(
                primary = %primary.fmt_short(),
                error = %format!("{e:#}"),
                "could not deliver unpair request; will retry"
            ),
            Err(_) => tracing::warn!(
                primary = %primary.fmt_short(),
                "timed out delivering unpair request; will retry"
            ),
        }
        if let Err(e) = config::update_settings(|cfg| {
            cfg.pending_unpair_request = Some(primary);
            Ok(())
        }) {
            tracing::warn!(error = %e, "failed to save unpair request for retry");
            return;
        }
        self.unpair_nudge.notify_one();
    }

    /// Retry the saved unpair request until its primary has received it, waiting
    /// [`UNPAIR_RETRY_MIN`] and then longer between attempts. A request saved
    /// before a restart is tried at once. With nothing saved this sleeps until
    /// [`Self::request_unpair`] saves something, so it costs no wakeups.
    pub(crate) async fn run_unpair_retries(self: Arc<Self>) {
        let mut pending = self.retry_unpair_request().await;
        let mut wait = UNPAIR_RETRY_MIN;
        loop {
            if !pending {
                tokio::select! {
                    _ = self.shutdown_token.cancelled() => return,
                    _ = self.unpair_nudge.notified() => wait = UNPAIR_RETRY_MIN,
                }
            }
            // A request was just saved because it could not be delivered, so
            // even the first retry waits.
            tokio::select! {
                _ = self.shutdown_token.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = (wait * 2).min(UNPAIR_RETRY_MAX);
            pending = self.retry_unpair_request().await;
        }
    }

    /// One attempt at the saved unpair request. Returns whether it is still
    /// waiting for its primary.
    pub(crate) async fn retry_unpair_request(&self) -> bool {
        let _guard = self.unpair_lock.lock().await;
        let primary = match config::load() {
            Ok(cfg) => cfg.pending_unpair_request,
            Err(e) => {
                tracing::debug!(error = %e, "failed to load config for unpair retry");
                return true;
            }
        };
        let Some(primary) = primary else {
            return false;
        };
        if self.current_device_cert().is_some() {
            tracing::info!(primary = %primary.fmt_short(), "paired again; dropping saved unpair request");
            clear_unpair_request(primary);
            return false;
        }
        match tokio::time::timeout(UNPAIR_REQUEST_TIMEOUT, self.deliver_unpair_request(primary))
            .await
        {
            Ok(Ok(())) => {
                tracing::info!(primary = %primary.fmt_short(), "delivered saved unpair request");
                clear_unpair_request(primary);
                false
            }
            Ok(Err(e)) => {
                tracing::debug!(primary = %primary.fmt_short(), error = %format!("{e:#}"), "unpair request retry failed");
                true
            }
            Err(_) => {
                tracing::debug!(primary = %primary.fmt_short(), "unpair request retry timed out");
                true
            }
        }
    }

    /// Send `RequestUnpair` to `primary` and wait until it has received it. Uses
    /// the live link when there is one. Otherwise a connection is dialed for the
    /// request alone, since a device that has left the networks it shared with
    /// its primary has none to dial it through.
    async fn deliver_unpair_request(&self, primary: EndpointId) -> Result<()> {
        #[cfg(target_os = "android")]
        self.wake_transport().await;
        let live = self
            .peers
            .conn_for_ip(&derive_ipv6(&primary))
            .filter(|conn| conn.close_reason().is_none());
        let dialed = live.is_none();
        let conn = match live {
            Some(conn) => conn,
            None => {
                transport::connect_to_peer_with_alpn(
                    &self.transport.endpoint,
                    primary,
                    &transport::mesh_alpn(),
                )
                .await?
            }
        };
        send_confirmed(&conn, None, &ControlMsg::RequestUnpair).await?;
        if dialed {
            // Received is not yet read, and closing the link discards what the
            // primary has not taken off the stream. Leave it a moment before the
            // connection drops, as `nuke` does for its one-off deliveries.
            let _ = tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
        }
        Ok(())
    }
}

/// Forget the saved unpair request to `primary`, unless a newer one replaced it.
fn clear_unpair_request(primary: EndpointId) {
    if let Err(e) = config::update_settings(|cfg| {
        if cfg.pending_unpair_request == Some(primary) {
            cfg.pending_unpair_request = None;
        }
        Ok(())
    }) {
        tracing::warn!(error = %e, "failed to clear unpair request");
    }
}
