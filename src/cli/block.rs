//! `ray block`, `ray unblock` and `ray blocked`: the connect-channel block
//! list, kept in the `blocked` setting so it rides the generic settings path.

use crate::*;
use ipc::{GlobalKey, NodeKey};

#[derive(serde::Serialize)]
#[serde(transparent)]
struct BlockedOutput(Vec<String>);

impl DisplayOut for BlockedOutput {
    fn print_human(&self) {
        if self.0.is_empty() {
            println!("no blocked peers");
        }
        for peer in &self.0 {
            println!("{peer}");
        }
    }
}

fn single_peer(peer: &str) -> Result<()> {
    anyhow::ensure!(
        !peer.trim().is_empty() && !peer.contains(',') && !peer.starts_with('-'),
        "a single peer name or identity is required"
    );
    Ok(())
}

/// Refuse a peer's connect requests and invitations.
pub(crate) async fn ipc_block(peer: &str) -> Result<()> {
    single_peer(peer)?;
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: NodeKey::Global(GlobalKey::Blocked),
        value: peer.to_string(),
        replace: false,
    })
    .await
}

/// Let a blocked peer reach this node again.
pub(crate) async fn ipc_unblock(peer: &str) -> Result<()> {
    single_peer(peer)?;
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: NodeKey::Global(GlobalKey::Blocked),
        value: format!("-{peer}"),
        replace: false,
    })
    .await
}

pub(crate) async fn ipc_blocked() -> Result<()> {
    let row = config_row(NodeKey::Global(GlobalKey::Blocked)).await?;
    printout(&BlockedOutput(
        row.split(',')
            .filter(|peer| !peer.is_empty())
            .map(str::to_string)
            .collect(),
    ))
}
