//! Unpairing a device from its primary, saved at each step so that a crash, a
//! restart or an unreachable peer leaves it to be finished rather than lost.
//!
//! Only the primary revokes a device network-wide: the nullifier rides the
//! signed blob, which only a network-key holder writes. Each side therefore
//! saves what is left to do before doing it, and keeps it until the other side
//! confirms:
//!
//! - A device that unpairs, by itself or when its primary tells it to, first
//!   saves a [`PendingUnpair`] holding the certificate it gives up. It then
//!   leaves the networks first joined with that certificate and deletes it, and
//!   only once those deletions are durable does the entry move on to
//!   [`UnpairPhase::Request`]. A start that finds an entry still in
//!   [`UnpairPhase::Cleanup`] finishes the cleanup before anything reads the
//!   certificate or restores a network ([`finish_interrupted_unpair`]).
//! - In the request phase the device asks its primary, over the pairing
//!   protocol, to record the revocation (`PairMsg::UnpairRequest`, carrying the
//!   certificate as the evidence of the pairing). The primary answers
//!   `PairMsg::UnpairRecorded` once the revocation is saved, also when it
//!   already was, and only that answer removes the entry. Until then the
//!   request is retried, at once after a start and then with a growing pause:
//!   once the device has left, neither side has another reason to dial the
//!   other.
//! - A primary too old for version 3 of the pairing protocol is sent the
//!   earlier `ControlMsg::RequestUnpair` instead, which revokes the device if
//!   its rosters still list it. Nothing confirms that, so the entry stays.
//! - Saving a new pairing with the same primary cancels the entry, which would
//!   otherwise revoke it. A pairing with another primary leaves it be.
//! - On the primary, `ray unpair <device>` saves the revocation and the device
//!   in `pending_unpair_notices` before telling the device
//!   (`ControlMsg::Unpaired`). The notice is repeated, after a restart too,
//!   until the device confirms with the same request, which it sends only once
//!   its cleanup is saved, or until the device pairs here again.

use super::super::network_registry::networks_joined_with_certificate;
use super::super::*;
use crate::config::{PendingUnpair, UnpairPhase};

#[cfg(test)]
mod tests;

/// How long one unpair request may take: the dial, then the primary saving the
/// revocation and republishing its networks. Past it the attempt has failed.
const UNPAIR_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long telling a device it is unpaired may take, the dial included.
const UNPAIR_NOTICE_TIMEOUT: Duration = Duration::from_secs(10);

/// The first pause before trying again, doubled after each miss up to
/// [`UNPAIR_RETRY_MAX`]. A peer can stay offline for days, and the device on
/// one end of it is usually a phone.
const UNPAIR_RETRY_MIN: Duration = Duration::from_secs(60);
const UNPAIR_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// What an unpair request got from the primary.
#[derive(Debug, PartialEq, Eq)]
enum RequestOutcome {
    /// The primary saved the revocation.
    Recorded,
    /// The primary predates the request and was sent the earlier
    /// `ControlMsg::RequestUnpair`, which nothing confirms.
    Legacy,
}

/// Finish the cleanup of each unpair that a restart interrupted, before
/// anything reads the device certificate or restores a network: the saved
/// networks first joined with the certificate are deleted, and so is the
/// certificate, as the interrupted unpair would have done. No network is live
/// yet, so none is told the device left; the primary's revocation removes it
/// from the networks the primary coordinates.
pub(crate) fn finish_interrupted_unpair() {
    let pending = match config::load() {
        Ok(cfg) => cfg.pending_unpairs,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not read saved unpairs");
            return;
        }
    };
    for entry in pending
        .iter()
        .filter(|entry| entry.phase == UnpairPhase::Cleanup)
    {
        let primary = entry.cert.user_identity;
        match finish_cleanup_offline(&entry.cert) {
            Ok(left) => tracing::info!(
                primary = %primary.fmt_short(),
                left,
                "finished an interrupted unpair"
            ),
            Err(error) => tracing::warn!(
                primary = %primary.fmt_short(),
                error = %format!("{error:#}"),
                "could not finish an interrupted unpair; it is retried"
            ),
        }
    }
}

/// The cleanup of an unpair from `cert` with no network live: delete the saved
/// networks first joined with it and, unless another pairing's certificate is
/// stored, the certificate, then [`complete_cleanup`]. Returns how many
/// networks were removed.
fn finish_cleanup_offline(cert: &control::DeviceCert) -> Result<usize> {
    let cfg = config::load()?;
    let names = networks_joined_with_certificate(&cfg.networks, cert.user_identity);
    for name in &names {
        config::delete_network(name)?;
    }
    match identity::load_device_cert() {
        Ok(Some(stored)) if stored != *cert => {}
        _ => identity::delete_device_cert()?,
    }
    complete_cleanup(cert)?;
    Ok(names.len())
}

/// Make the cleanup of the unpair from `cert` durable, then move its entry on
/// to the request, which is also the device's confirmation that the cleanup is
/// done.
fn complete_cleanup(cert: &control::DeviceCert) -> Result<()> {
    config::sync_deletions()?;
    config::update_settings(|cfg| {
        for entry in &mut cfg.pending_unpairs {
            if entry.cert == *cert {
                entry.phase = UnpairPhase::Request;
            }
        }
        Ok(())
    })?;
    Ok(())
}

/// Remove the saved unpair from `cert`, confirmed or cancelled. Returns whether
/// it is gone.
fn remove_pending_unpair(cert: &control::DeviceCert) -> bool {
    match config::update_settings(|cfg| {
        cfg.pending_unpairs.retain(|entry| entry.cert != *cert);
        Ok(())
    }) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not remove a saved unpair");
            false
        }
    }
}

/// Run `attempt` at once, whenever `nudge` fires, and, while it reports work
/// left, again after a pause that starts at [`UNPAIR_RETRY_MIN`] and doubles up
/// to [`UNPAIR_RETRY_MAX`]. A nudge also resets the pause. With nothing left it
/// waits for a nudge alone, so it costs no wakeups.
async fn retry_until_done<F, Fut>(shutdown: &CancellationToken, nudge: &Notify, mut attempt: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut wait = UNPAIR_RETRY_MIN;
    loop {
        let left = attempt().await;
        let pause = async {
            if left {
                tokio::time::sleep(wait).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = nudge.notified() => wait = UNPAIR_RETRY_MIN,
            _ = pause => wait = (wait * 2).min(UNPAIR_RETRY_MAX),
        }
    }
}

impl NetworkRegistry {
    /// Unpair this device from its primary: save the unpair, leave the networks
    /// first joined with the primary's certificate and delete it, then, once
    /// that is durable, ask the primary to record the revocation (see the
    /// module docs). Used by the phone's unpair control, the primary's
    /// `ControlMsg::Unpaired`, and a signed blob that nullifies this device. A
    /// device with no cert (a primary) has nothing to unpair.
    pub(crate) async fn unpair_self(self: &Arc<Self>) -> IpcMessage {
        let _guard = self.unpair_lock.lock().await;
        self.unpair_self_locked().await
    }

    /// [`Self::unpair_self`], for a caller holding the unpair lock.
    async fn unpair_self_locked(self: &Arc<Self>) -> IpcMessage {
        let Some(cert) = self.current_device_cert() else {
            return ipc_err("this device is not paired to a primary".to_string());
        };
        // Saved before any of the work, so a restart finishes it.
        if let Err(error) = config::update_settings(|cfg| {
            cfg.pending_unpairs
                .retain(|entry| entry.cert.user_identity != cert.user_identity);
            cfg.pending_unpairs.push(PendingUnpair {
                cert: cert.clone(),
                phase: UnpairPhase::Cleanup,
            });
            Ok(())
        }) {
            return ipc_err(format!("could not save the unpair: {error:#}"));
        }
        let left = self.finish_cleanup_locked(&cert).await;
        self.unpair_nudge.notify_one();
        left
    }

    /// The cleanup of the saved unpair from `cert`, made durable and moved on to
    /// its request. Caller holds the unpair lock.
    async fn finish_cleanup_locked(self: &Arc<Self>, cert: &control::DeviceCert) -> IpcMessage {
        let left = self.leave_certificate_networks(cert).await;
        if !matches!(left, IpcMessage::Ok { .. }) {
            return left;
        }
        if let Err(error) = complete_cleanup(cert) {
            return ipc_err(format!(
                "left the primary's networks and deleted its certificate, but could not \
                 save that ({error:#}); it is retried"
            ));
        }
        left
    }

    /// The primary's `ControlMsg::Unpaired`, from `sender`. Unpairs this device
    /// when `sender` signed its certificate, unless a pairing completed since
    /// the notice arrived (`pairings_seen` was read then): a notice the primary
    /// sent before that pairing is not about it. A device that already unpaired
    /// from `sender` and still waits for it to confirm asks again at once, since
    /// the primary is reachable now.
    pub(crate) async fn on_unpaired_notice(
        self: &Arc<Self>,
        sender: EndpointId,
        pairings_seen: u64,
    ) {
        let _guard = self.unpair_lock.lock().await;
        if self.pairing_count.load(Ordering::Acquire) != pairings_seen {
            tracing::info!(primary = %sender.fmt_short(), "ignoring an unpair notice from before this device paired again");
            return;
        }
        if self
            .current_device_cert()
            .is_some_and(|cert| cert.user_identity == sender)
        {
            tracing::warn!(primary = %sender.fmt_short(), "primary unpaired this device");
            let _ = self.unpair_self_locked().await;
            return;
        }
        let waiting = config::load().is_ok_and(|cfg| {
            cfg.pending_unpairs
                .iter()
                .any(|entry| entry.cert.user_identity == sender)
        });
        if waiting {
            self.unpair_nudge.notify_one();
        }
    }

    /// A new pairing with `primary` is saved: cancel this device's request to be
    /// unpaired from it, which would otherwise revoke the new pairing, and make
    /// earlier notices stale (see [`Self::on_unpaired_notice`]). Caller holds
    /// the unpair lock. If the cancel cannot be saved, the next attempt at the
    /// request finds the new certificate and cancels it then.
    pub(crate) fn paired_again(&self, primary: EndpointId) {
        if let Err(error) = config::update_settings(|cfg| {
            cfg.pending_unpairs
                .retain(|entry| entry.cert.user_identity != primary);
            Ok(())
        }) {
            tracing::warn!(error = %format!("{error:#}"), "could not cancel the unpair request to this primary");
        }
        self.pairing_count.fetch_add(1, Ordering::AcqRel);
    }

    /// Finish the cleanup of any saved unpair still in that phase, which only a
    /// start that failed to finish it leaves, so that a pairing never starts
    /// under one. Caller holds the unpair lock.
    pub(crate) async fn finish_cleanups_locked(self: &Arc<Self>) -> Result<(), String> {
        let pending = config::load()
            .map_err(|error| format!("could not read saved unpairs: {error:#}"))?
            .pending_unpairs;
        for entry in pending {
            if entry.phase != UnpairPhase::Cleanup {
                continue;
            }
            if let IpcMessage::Error { message } = self.finish_cleanup_locked(&entry.cert).await {
                return Err(message);
            }
        }
        Ok(())
    }

    /// Drive this device's saved unpairs to completion: at once when the daemon
    /// starts or [`Self::unpair_nudge`] fires, and while any is left, again
    /// after a pause growing from [`UNPAIR_RETRY_MIN`] to [`UNPAIR_RETRY_MAX`].
    /// Spawned on every build, so the mobile embedder gets it: a phone is what
    /// unpairs itself.
    pub(crate) async fn run_unpair_requests(self: Arc<Self>) {
        let nudge = Arc::clone(&self.unpair_nudge);
        retry_until_done(&self.shutdown_token, &nudge, || {
            self.attempt_unpair_requests()
        })
        .await;
    }

    /// One attempt at each of this device's saved unpairs: finish a cleanup the
    /// start could not, and send each request. Returns whether any is left.
    pub(crate) async fn attempt_unpair_requests(self: &Arc<Self>) -> bool {
        let _guard = self.unpair_lock.lock().await;
        let pending = match config::load() {
            Ok(cfg) => cfg.pending_unpairs,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "could not read saved unpairs");
                return true;
            }
        };
        let stored = self.current_device_cert();
        let mut left = false;
        for entry in pending {
            let primary = entry.cert.user_identity;
            if entry.phase == UnpairPhase::Cleanup {
                if let IpcMessage::Error { message } = self.finish_cleanup_locked(&entry.cert).await
                {
                    tracing::warn!(primary = %primary.fmt_short(), %message, "could not finish an unpair");
                } else {
                    // Its request is next, without waiting for the pause.
                    self.unpair_nudge.notify_one();
                }
                left = true;
                continue;
            }
            // Pairing again saves the new certificate before it cancels the
            // request, and in this phase the old one is already deleted, so a
            // stored certificate from this primary is a new pairing that a
            // restart kept from cancelling it.
            if stored
                .as_ref()
                .is_some_and(|cert| cert.user_identity == primary)
            {
                tracing::info!(primary = %primary.fmt_short(), "paired with this primary again; cancelling the unpair request");
                left |= !remove_pending_unpair(&entry.cert);
                continue;
            }
            match tokio::time::timeout(
                UNPAIR_REQUEST_TIMEOUT,
                self.send_unpair_request(&entry.cert),
            )
            .await
            {
                Ok(Ok(RequestOutcome::Recorded)) => {
                    tracing::info!(primary = %primary.fmt_short(), "primary recorded this device's unpair");
                    left |= !remove_pending_unpair(&entry.cert);
                }
                Ok(Ok(RequestOutcome::Legacy)) => {
                    tracing::debug!(primary = %primary.fmt_short(), "primary predates unpair requests; sent it the earlier one");
                    left = true;
                }
                Ok(Err(error)) => {
                    tracing::debug!(primary = %primary.fmt_short(), error = %format!("{error:#}"), "unpair request failed");
                    left = true;
                }
                Err(_) => {
                    tracing::debug!(primary = %primary.fmt_short(), "unpair request timed out");
                    left = true;
                }
            }
        }
        left
    }

    /// Ask the primary that signed `cert` to record this device's revocation.
    /// A primary on version 2 of the pairing protocol cannot, so it is sent the
    /// earlier `ControlMsg::RequestUnpair` instead.
    async fn send_unpair_request(&self, cert: &control::DeviceCert) -> Result<RequestOutcome> {
        #[cfg(target_os = "android")]
        self.wake_transport().await;
        let primary = cert.user_identity;
        let conn = connect_pair(&self.transport.endpoint, primary.into()).await?;
        if conn.alpn() != PAIR_ALPN {
            conn.close(VarInt::from_u32(0), b"older pairing protocol");
            self.deliver_control(primary, &ControlMsg::RequestUnpair)
                .await?;
            return Ok(RequestOutcome::Legacy);
        }
        let (mut send, mut recv) = conn.open_bi().await.context("open unpair stream")?;
        let request = control::PairMsg::UnpairRequest { cert: cert.clone() };
        control::send_framed(&mut send, &request).await?;
        let reply: control::PairMsg = control::recv_framed(&mut recv)
            .await
            .context("read unpair reply")?;
        conn.close(VarInt::from_u32(0), b"done");
        match reply {
            control::PairMsg::UnpairRecorded => Ok(RequestOutcome::Recorded),
            _ => anyhow::bail!("unexpected reply to an unpair request"),
        }
    }

    /// Send `msg`, a connection-level control message, to `peer` and wait until
    /// it has taken it. Uses the live link when there is one. Otherwise a link
    /// is dialed for the message alone, since an unpaired device and its primary
    /// may share no network any more.
    async fn deliver_control(&self, peer: EndpointId, msg: &ControlMsg) -> Result<()> {
        #[cfg(target_os = "android")]
        self.wake_transport().await;
        let live = self
            .peers
            .conn_for_ip(&derive_ipv6(&peer))
            .filter(|conn| conn.close_reason().is_none());
        let dialed = live.is_none();
        let conn = match live {
            Some(conn) => conn,
            None => {
                transport::connect_to_peer_with_alpn(
                    &self.transport.endpoint,
                    peer,
                    &transport::mesh_alpn(),
                )
                .await?
            }
        };
        send_confirmed(&conn, None, msg).await?;
        if dialed {
            // Taken off the stream, but closing at once can still reset it
            // before the peer's reader is done with it. Leave it a moment, as
            // `nuke` does for its one-off deliveries.
            let _ = tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
        }
        Ok(())
    }

    /// Tell each device in `pending_unpair_notices` that it is unpaired: at once
    /// when the daemon starts or [`Self::notice_nudge`] fires, and while any is
    /// left, again after the same growing pause as the requests.
    pub(crate) async fn run_unpair_notices(self: Arc<Self>) {
        let nudge = Arc::clone(&self.notice_nudge);
        retry_until_done(&self.shutdown_token, &nudge, || {
            self.attempt_unpair_notices()
        })
        .await;
    }

    /// One `ControlMsg::Unpaired` to each device still to be told. Returns
    /// whether any is left: told or not, a device stays until it confirms
    /// ([`Self::record_unpair`]) or pairs here again
    /// ([`Self::cancel_unpair_notice`]).
    pub(crate) async fn attempt_unpair_notices(&self) -> bool {
        let devices = match config::load() {
            Ok(cfg) => cfg.pending_unpair_notices,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "could not read devices to tell they are unpaired");
                return true;
            }
        };
        for device in &devices {
            let _guard = self.notice_lock.lock().await;
            if !config::load().is_ok_and(|cfg| cfg.pending_unpair_notices.contains(device)) {
                continue;
            }
            match tokio::time::timeout(
                UNPAIR_NOTICE_TIMEOUT,
                self.deliver_control(*device, &ControlMsg::Unpaired),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::debug!(device = %device.fmt_short(), "told device it is unpaired; waiting for it to confirm")
                }
                Ok(Err(error)) => {
                    tracing::debug!(device = %device.fmt_short(), error = %format!("{error:#}"), "could not tell device it is unpaired")
                }
                Err(_) => {
                    tracing::debug!(device = %device.fmt_short(), "timed out telling device it is unpaired")
                }
            }
        }
        !devices.is_empty()
    }

    /// Record the unpair a paired device asked for with the certificate this
    /// node signed for it, which the caller checked: revoke the device
    /// ([`Self::revoke_device`]) and, in the same write, stop telling it to
    /// unpair, since a device asks only once its cleanup is saved.
    pub(crate) async fn record_unpair(self: &Arc<Self>, device: EndpointId) -> Result<(), String> {
        self.revoke_device(device, |cfg| {
            cfg.pending_unpair_notices
                .retain(|pending| *pending != device);
        })
        .await
    }

    /// Stop telling `device` that it is unpaired: it is pairing here again. A
    /// notice being sent finishes first, so none reaches the device after its
    /// new pairing.
    pub(crate) async fn cancel_unpair_notice(&self, device: EndpointId) -> Result<()> {
        let _guard = self.notice_lock.lock().await;
        config::update_settings(|cfg| {
            cfg.pending_unpair_notices
                .retain(|pending| *pending != device);
            Ok(())
        })?;
        Ok(())
    }
}
