//! Sending private invitations (`ray apply --invite-missing`).
//!
//! The outbox is the invite ledger: a delivery invite keeps its code so every
//! retry offers the same credential. A delivery is dialed to the recipient's
//! identity and counts as delivered only when the recipient's daemon acks it.
//! An unreachable recipient is not an error: the sweep retries until the
//! invite expires, is redeemed, or is revoked, and never mints a new one.

use super::*;
use crate::invite::{Invite, InviteStore};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// What a delivery attempt did. Both are success for the caller: a queued
/// delivery is retried by the sweep.
enum DeliveryOutcome {
    Done(String),
    Queued(String),
}

impl ConnectService {
    /// `InviteDeliver`: deliver (or reuse and redeliver) an invite to
    /// `recipient` for `network`.
    pub(super) async fn deliver_invite(&self, network: &str, recipient: EndpointId) -> IpcMessage {
        match self.deliver_locked(network, recipient, true).await {
            Ok(DeliveryOutcome::Done(message) | DeliveryOutcome::Queued(message)) => {
                IpcMessage::Ok { message }
            }
            Err(e) => ipc_err(e.to_string()),
        }
    }

    /// One delivery per recipient at a time, so a slow dial to one recipient
    /// never holds up another.
    async fn deliver_locked(
        &self,
        network: &str,
        recipient: EndpointId,
        mint: bool,
    ) -> Result<DeliveryOutcome> {
        let lock = Arc::clone(
            &self
                .delivery_locks
                .entry(recipient)
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        );
        let _guard = lock.lock().await;
        self.deliver_inner(network, recipient, mint).await
    }

    async fn deliver_inner(
        &self,
        network: &str,
        recipient: EndpointId,
        mint: bool,
    ) -> Result<DeliveryOutcome> {
        let (network_key, invite_lock) =
            self.registry.coordinator_handle(network).map_err(|_| {
                anyhow::anyhow!("invite delivery requires a network this node coordinates")
            })?;
        if self.recipient_joined(network, recipient) {
            return Ok(DeliveryOutcome::Done(format!(
                "{} already has a device in {network}",
                recipient.fmt_short()
            )));
        }
        let invite: Invite = {
            let _guard = invite_lock.lock().await;
            let mut store = InviteStore::load(network)?;
            if mint {
                store.delivery_for(recipient, network_key, self.transport.endpoint.id())?
            } else {
                // A sweep never mints: redemption, revocation or expiry since
                // it picked this recipient means there is nothing to resend.
                match store.live_delivery(recipient) {
                    Some(invite) => invite,
                    None => return Ok(DeliveryOutcome::Done("no pending delivery".to_string())),
                }
            }
        };
        let delivery = invite.delivery.context("delivery invite missing")?;
        if delivery.delivered {
            return Ok(DeliveryOutcome::Done(format!(
                "invite {} already delivered; awaiting the recipient",
                invite.id
            )));
        }
        let offer = control::ConnectMsg::InviteOffer {
            network: ipc::NetworkName::new(network.to_string()),
            code: delivery.code,
        };
        let acked = tokio::time::timeout(DELIVERY_TIMEOUT, async {
            let conn = transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                recipient,
                transport::CONNECT_ALPN,
            )
            .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            control::send_framed(&mut send, &offer).await?;
            // Never echo a peer reply: only the ack shape matters.
            match control::recv_framed::<control::ConnectMsg>(&mut recv).await? {
                control::ConnectMsg::Pending => Ok(()),
                _ => anyhow::bail!("recipient did not acknowledge"),
            }
        })
        .await;
        if !matches!(acked, Ok(Ok(()))) {
            return Ok(DeliveryOutcome::Queued(format!(
                "{} is unreachable; invite {} queued and retried until it expires",
                recipient.fmt_short(),
                invite.id
            )));
        }
        {
            let _guard = invite_lock.lock().await;
            InviteStore::load(network)?.mark_delivered(&invite.id)?;
        }
        Ok(DeliveryOutcome::Done(format!(
            "invite {} delivered; awaiting the recipient",
            invite.id
        )))
    }

    /// Whether any device of `recipient` (device or user identity) is already a
    /// member of `network`.
    fn recipient_joined(&self, network: &str, recipient: EndpointId) -> bool {
        self.registry.networks.get(network).is_some_and(|handle| {
            handle.state.read().is_ok_and(|state| {
                state
                    .members
                    .all()
                    .iter()
                    .any(|member| member.matches_identity(recipient))
            })
        })
    }

    /// Retry undelivered invites every minute until the daemon stops.
    pub(crate) fn start_invite_delivery(self: &Arc<Self>, token: CancellationToken) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(RETRY_INTERVAL) => {}
                }
                service.sweep_deliveries(&token).await;
            }
        });
    }

    async fn sweep_deliveries(&self, token: &CancellationToken) {
        let networks: Vec<String> = self
            .registry
            .networks
            .iter()
            .filter(|n| n.role.is_coordinator())
            .map(|n| n.key().clone())
            .collect();
        for network in networks {
            let recipients = match InviteStore::load(&network) {
                Ok(store) => store.pending_deliveries(),
                Err(_) => {
                    tracing::warn!(%network, "could not read the invite ledger for delivery");
                    continue;
                }
            };
            for recipient in recipients {
                tokio::select! {
                    _ = token.cancelled() => return,
                    outcome = self.deliver_locked(&network, recipient, false) => {
                        if !matches!(outcome, Ok(DeliveryOutcome::Done(_))) {
                            tracing::debug!(%network, peer = %recipient.fmt_short(), "invite still queued");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
impl ConnectService {
    /// One sweep pass, for tests that cannot wait a minute.
    pub(super) async fn sweep_once(&self) {
        self.sweep_deliveries(&CancellationToken::new()).await;
    }

    /// The sweep's per-recipient step, which must never mint.
    pub(super) async fn redeliver(&self, network: &str, recipient: EndpointId) -> String {
        match self.deliver_locked(network, recipient, false).await {
            Ok(DeliveryOutcome::Done(message) | DeliveryOutcome::Queued(message)) => message,
            Err(e) => e.to_string(),
        }
    }
}
