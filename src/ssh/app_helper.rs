//! SSH for the macOS app, outside NetworkExtension's socket policy.
//!
//! launchd owns a root-only Unix socket and starts the bundled CLI helper. The
//! packet tunnel connects, supplies its mesh address, then authorizes each TCP
//! connection using its live peer registry. No policy snapshot is cached here.
//! Both ends check the Unix peer UID. The helper owns every TCP socket and login
//! process; EOF on the control stream closes listeners and sessions. This is a
//! private, versioned local protocol, not mesh or CLI IPC.

use std::ffi::{c_char, c_int};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use russh::keys::{PrivateKey, ssh_key::LineEnding};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use super::{
    Config, LOGIN_GRACE, Origin, SSH_LISTEN_PORT, SSH_PORT, SshAuthz, SshHandler, UserPolicy,
    auth_banner, disable_nagle, load_host_key, resolve_user_policy_with_hostnames, serve,
    server_config,
};
use crate::daemon::NetworkRegistry;

const SOCKET: &str = "/var/run/com.rayfish.app.ssh.sock";
const VERSION: u32 = 1;
const MAX_FRAME: usize = 64 * 1024;
const MAX_SESSIONS: usize = 128;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Hello {
    version: u32,
    address: Ipv6Addr,
    // Sent only after authenticating the root helper. Discovery stays in the
    // provider to preserve its app-group fallback key, without touching the
    // standalone daemon's state. Never include this message in diagnostics.
    host_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Ready {
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct Authorize {
    client: SocketAddr,
}

#[derive(Serialize, Deserialize)]
struct Grant {
    user: EndpointId,
    policy: UserPolicy,
    banner: Option<String>,
}

async fn send<T: Serialize>(writer: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<()> {
    let bytes = rmp_serde::to_vec_named(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "SSH helper frame too large");
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

async fn receive<T: DeserializeOwned>(reader: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let len = reader.read_u32().await? as usize;
    ensure!(len <= MAX_FRAME, "SSH helper frame too large");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(rmp_serde::from_slice(&bytes)?)
}

fn require_root_peer(stream: &UnixStream) -> Result<()> {
    ensure!(
        stream.peer_cred()?.uid() == 0,
        "SSH helper requires a root peer"
    );
    Ok(())
}

fn validate_hello(hello: &Hello) -> Result<()> {
    ensure!(
        hello.version == VERSION,
        "SSH helper version mismatch; restart Rayfish"
    );
    ensure!(
        hello.address.segments()[0] & 0xfe00 == 0x0200,
        "SSH helper requires a mesh address"
    );
    Ok(())
}

/// Called only for an OS-owned macOS tunnel. The daemon keeps its own listener.
pub(crate) fn spawn(
    address: Ipv6Addr,
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => return,
                result = authorize_connections(address, &registry, &authz) => {
                    crate::forward::set_ssh_nat_active(false);
                    if let Err(error) = result {
                        tracing::warn!(%error, "macOS SSH helper unavailable; enable Rayfish in Login Items & Extensions");
                    }
                }
            }
            tokio::select! {
                biased;
                _ = token.cancelled() => return,
                _ = sleep(CONTROL_TIMEOUT) => {}
            }
        }
    });
}

async fn authorize_connections(
    address: Ipv6Addr,
    registry: &NetworkRegistry,
    authz: &SshAuthz,
) -> Result<()> {
    let mut control = timeout(CONTROL_TIMEOUT, async {
        let meta = tokio::fs::symlink_metadata(SOCKET).await?;
        ensure!(
            meta.file_type().is_socket() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
            "SSH helper socket must be root-owned and private"
        );
        let mut stream = UnixStream::connect(SOCKET).await?;
        require_root_peer(&stream)?;
        send(
            &mut stream,
            &Hello {
                version: VERSION,
                address,
                host_key: load_host_key()?
                    .to_openssh(LineEnding::LF)?
                    .as_bytes()
                    .to_vec(),
            },
        )
        .await?;
        let ready: Ready = receive(&mut stream).await?;
        ensure!(ready.version == VERSION, "SSH helper version mismatch");
        Ok::<_, anyhow::Error>(stream)
    })
    .await??;
    crate::forward::set_ssh_nat_active(true);
    tracing::info!(%address, "macOS app SSH helper ready");
    loop {
        let request: Authorize = receive(&mut control).await?;
        let grant = grant_for(request.client, address, registry, authz);
        timeout(CONTROL_TIMEOUT, send(&mut control, &grant)).await??;
    }
}

fn grant_for(
    client: SocketAddr,
    local: Ipv6Addr,
    registry: &NetworkRegistry,
    authz: &SshAuthz,
) -> Option<Grant> {
    let IpAddr::V6(source) = client.ip() else {
        return None;
    };
    // Local connections do not carry a mesh identity proof.
    if source == local {
        return None;
    }
    let peer = registry.peers.identity_for_ip(&source)?;
    let user = registry.device_user_map.resolve(&peer);
    let networks = registry.authorization_networks(peer);
    let resolve = |network: &str, hostname: &str| {
        registry
            .resolve_peer_in_network(network, hostname)
            .map(|id| registry.device_user_map.resolve(&id))
    };
    let policy = resolve_user_policy_with_hostnames(authz, &user, &networks, &resolve);
    let banner = auth_banner(&policy, &user, &networks);
    tracing::debug!(%client, peer = %user.fmt_short(), authorized = policy.authorized(),
        "macOS app SSH authorization");
    Some(Grant {
        user,
        policy,
        banner,
    })
}

/// Entry point for the app's hidden CLI command, launched by SMAppService.
pub async fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "SSH helper must run as root through launchd"
    );
    let listener = activated_listener()?;
    loop {
        let (mut control, _) = listener.accept().await?;
        if let Err(error) = require_root_peer(&control) {
            tracing::warn!(%error, "SSH helper refused control connection");
            continue;
        }
        let result = async {
            let hello: Hello = timeout(CONTROL_TIMEOUT, receive(&mut control)).await??;
            validate_hello(&hello)?;
            // Do not enable SO_REUSEPORT: another listener must never share these
            // identity-authorized sessions, even when a helper is being replaced.
            let tcp = TcpListener::bind((hello.address, SSH_LISTEN_PORT)).await?;
            let config = Arc::new(server_config(PrivateKey::from_openssh(&hello.host_key)?));
            run_listener(control, tcp, config).await
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(%error, "macOS SSH helper session stopped");
        }
        // launchd starts the current bundled executable on the next connection.
        // Do not retain an old helper across an app update or VPN reconnect.
        return Ok(());
    }
}

// A cloned socket is only a shutdown handle; the SSH session owns all I/O.
struct Hangup(StdTcpStream);

impl Drop for Hangup {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

async fn run_listener(
    mut control: UnixStream,
    listener: TcpListener,
    config: Arc<Config>,
) -> Result<()> {
    timeout(
        CONTROL_TIMEOUT,
        send(&mut control, &Ready { version: VERSION }),
    )
    .await??;
    let mut sessions = JoinSet::new();
    loop {
        let mut unexpected = [0];
        let (stream, client) = tokio::select! {
            biased;
            // Outside a request/reply exchange, any input is EOF or a protocol
            // violation. Dropping the JoinSet also drops every Hangup guard.
            read = control.read(&mut unexpected) => {
                read?;
                bail!("SSH helper control connection closed or sent unexpected data");
            }
            _ = sessions.join_next(), if !sessions.is_empty() => continue,
            accepted = listener.accept(), if sessions.len() < MAX_SESSIONS => accepted?,
        };
        let grant: Option<Grant> = timeout(CONTROL_TIMEOUT, async {
            send(&mut control, &Authorize { client }).await?;
            receive(&mut control).await
        })
        .await??;
        let Some(grant) = grant else { continue };
        disable_nagle(&stream);
        let server = SocketAddr::new(stream.local_addr()?.ip(), SSH_PORT);
        let hangup = Hangup(StdTcpStream::from(stream.as_fd().try_clone_to_owned()?));
        let handler = SshHandler::new(
            grant.policy,
            grant.user,
            grant.banner,
            Origin { client, server },
        );
        let config = Arc::clone(&config);
        sessions.spawn(async move {
            let _hangup = hangup;
            serve(config, stream, handler, LOGIN_GRACE).await;
        });
    }
}

fn activated_listener() -> Result<UnixListener> {
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            fds: *mut *mut c_int,
            count: *mut usize,
        ) -> c_int;
    }
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    let result = unsafe { launch_activate_socket(c"Control".as_ptr(), &mut fds, &mut count) };
    ensure!(
        result == 0,
        "SSH helper requires its launchd Control socket (error {result})"
    );
    if fds.is_null() || count == 0 {
        unsafe { libc::free(fds.cast()) };
        bail!("launchd supplied no SSH helper Control socket");
    }
    // launch_activate_socket transfers the descriptors and a malloc'd array.
    let sockets: Vec<OwnedFd> = unsafe {
        let sockets = std::slice::from_raw_parts(fds, count)
            .iter()
            .map(|fd| OwnedFd::from_raw_fd(*fd))
            .collect();
        libc::free(fds.cast());
        sockets
    };
    ensure!(sockets.len() == 1, "expected one SSH helper Control socket");
    let socket = StdUnixListener::from(
        sockets
            .into_iter()
            .next()
            .context("missing Control socket")?,
    );
    socket.set_nonblocking(true)?;
    Ok(UnixListener::from_std(socket)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client;
    use russh::keys::{Algorithm, PublicKey};
    use tokio::net::TcpStream;

    struct AcceptTestKey;

    impl client::Handler for AcceptTestKey {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _: &PublicKey) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn test_config() -> Result<Arc<Config>> {
        Ok(Arc::new(server_config(PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Ed25519,
        )?)))
    }

    #[test]
    fn refuses_non_mesh_addresses_and_other_versions() -> Result<()> {
        for address in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            "fe80::1".parse()?,
        ] {
            assert!(
                validate_hello(&Hello {
                    version: VERSION,
                    address,
                    host_key: Vec::new(),
                })
                .is_err()
            );
        }
        let address = "290::1".parse()?;
        assert!(
            validate_hello(&Hello {
                version: VERSION,
                address,
                host_key: Vec::new(),
            })
            .is_ok()
        );
        assert!(
            validate_hello(&Hello {
                version: VERSION + 1,
                address,
                host_key: Vec::new(),
            })
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_unprivileged_control_peers() -> Result<()> {
        let (control, _other) = UnixStream::pair()?;
        assert_eq!(
            require_root_peer(&control).is_ok(),
            unsafe { libc::geteuid() } == 0
        );
        Ok(())
    }

    #[tokio::test]
    async fn oversized_control_frame_is_rejected_before_allocating_payload() -> Result<()> {
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_u32(MAX_FRAME as u32 + 1).await?;
        assert!(
            receive::<Hello>(&mut receiver)
                .await
                .err()
                .context("oversized frame was accepted")?
                .to_string()
                .contains("too large")
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_peer_is_closed_and_control_eof_releases_listener() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let task = tokio::spawn(run_listener(control, tcp, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let mut client = TcpStream::connect(address).await?;
        let request: Authorize = receive(&mut provider).await?;
        assert_eq!(request.client, client.local_addr()?);
        send(&mut provider, &None::<Grant>).await?;
        let mut byte = [0];
        assert_eq!(timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await??, 0);
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, task).await??.is_err());
        assert!(TcpListener::bind(address).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn control_eof_closes_a_session_waiting_for_ssh_handshake() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let task = tokio::spawn(run_listener(control, tcp, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let mut client = TcpStream::connect(address).await?;
        let _: Authorize = receive(&mut provider).await?;
        let mut policy = UserPolicy::default();
        policy.add(&[]);
        send(
            &mut provider,
            &Some(Grant {
                user: iroh::SecretKey::generate().public(),
                policy,
                banner: None,
            }),
        )
        .await?;
        let mut banner = [0; 128];
        let n = timeout(CONTROL_TIMEOUT, client.read(&mut banner)).await??;
        assert!(banner[..n].starts_with(b"SSH-2.0-"));
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, task).await??.is_err());
        let mut remaining = Vec::new();
        timeout(CONTROL_TIMEOUT, client.read_to_end(&mut remaining)).await??;
        Ok(())
    }

    #[tokio::test]
    async fn helper_enforces_nonroot_policy_received_over_control_socket() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let server = tokio::spawn(run_listener(control, tcp, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let client = tokio::spawn(async move {
            let mut connection =
                client::connect(Arc::new(client::Config::default()), address, AcceptTestKey)
                    .await?;
            Ok::<_, anyhow::Error>(connection.authenticate_none("root").await?.success())
        });
        let _: Authorize = receive(&mut provider).await?;
        let mut policy = UserPolicy::default();
        policy.add(&[]);
        send(
            &mut provider,
            &Some(Grant {
                user: iroh::SecretKey::generate().public(),
                policy,
                banner: None,
            }),
        )
        .await?;
        assert!(!timeout(CONTROL_TIMEOUT, client).await???);
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, server).await??.is_err());
        Ok(())
    }
}
