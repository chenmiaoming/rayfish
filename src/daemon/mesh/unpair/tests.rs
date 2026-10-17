//! Unpairs between real daemons: a primary and its paired device, each built
//! from a config tree of its own and run on a runtime whose threads read that
//! tree (`config::set_thread_config_dir`), since the config directory is
//! otherwise process-wide. A local discovery relay stands in for the public
//! one, and a daemon learns the other's address as a warm hint, the way an
//! earlier connection leaves it.

use iroh::RelayMode;
use iroh::endpoint::presets;

use super::super::destruction::tests::Relay;
use super::*;

/// A daemon with a config tree of its own. Anything that reads config runs
/// through [`Node::run`], on the node's runtime.
struct Node {
    /// The node's identity, stored before its daemon first starts.
    key: SecretKey,
    runtime: Option<tokio::runtime::Runtime>,
    daemon: Option<Arc<Daemon>>,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn new(relay: &Relay) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || config::set_thread_config_dir(tree.clone()))
            .build()
            .unwrap();
        let node = Self {
            key: SecretKey::generate(),
            runtime: Some(runtime),
            daemon: None,
            _dir: dir,
        };
        let key = node.key.clone();
        let relay = relay.url.to_string();
        node.run(async move {
            identity::store_secret_key(&key).unwrap();
            config::update_settings(|cfg| {
                cfg.mdns_enabled = false;
                cfg.discovery_dns = config::ServerOverride {
                    servers: vec![relay],
                    replace: true,
                };
                Ok(())
            })
            .unwrap();
        })
        .await;
        node
    }

    fn id(&self) -> EndpointId {
        self.key.public()
    }

    /// Run `task` on this node, where config reads go to its tree.
    async fn run<T: Send + 'static>(&self, task: impl Future<Output = T> + Send + 'static) -> T {
        self.runtime.as_ref().unwrap().spawn(task).await.unwrap()
    }

    async fn start(&mut self) {
        let daemon = self
            .run(async { build_headless(false).await.unwrap() })
            .await;
        self.daemon = Some(daemon);
    }

    /// Shut the daemon down: the node is offline until started again.
    async fn stop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            self.run(async move { daemon.shutdown_and_close().await })
                .await;
        }
    }

    fn daemon(&self) -> Arc<Daemon> {
        Arc::clone(self.daemon.as_ref().expect("daemon is running"))
    }

    async fn settings(&self) -> config::AppConfig {
        self.run(async { config::load().unwrap() }).await
    }

    async fn cert(&self) -> Option<control::DeviceCert> {
        self.run(async { identity::load_device_cert().unwrap() })
            .await
    }

    async fn has_network(&self, name: &'static str) -> bool {
        self.run(async move { config::load_network(name).unwrap().is_some() })
            .await
    }

    /// Whether the live `name` nullifies `device`.
    fn nullifies(&self, name: &str, device: EndpointId) -> bool {
        let daemon = self.daemon();
        let handle = daemon.registry.networks.get(name).expect("network is live");
        handle.state.read().unwrap().nullifiers.contains(&device)
    }

    async fn unpair_self(&self) -> IpcMessage {
        let daemon = self.daemon();
        self.run(async move { daemon.unpair_self().await }).await
    }

    /// One attempt at this device's saved unpairs. Returns whether any is left.
    async fn attempt_requests(&self) -> bool {
        let daemon = self.daemon();
        self.run(async move { daemon.registry.attempt_unpair_requests().await })
            .await
    }

    /// Wait, at most 30 s, until `check` holds for this node's settings.
    async fn eventually(
        &self,
        what: &str,
        check: impl Fn(&config::AppConfig) -> bool + Clone + Send + 'static,
    ) {
        for _ in 0..300 {
            let check = check.clone();
            if self
                .run(async move { config::load().is_ok_and(|cfg| check(&cfg)) })
                .await
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // From inside the test's runtime, where a blocking shutdown panics.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Hand `from` the address `to` listens on, as a warm hint would.
fn introduce(from: &Node, to: &Node) {
    from.daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(to.daemon().transport.endpoint.addr());
}

async fn create(daemon: &Daemon, name: &str) {
    let result = daemon
        .create_network(
            GroupMode::Restricted,
            Some(name.to_string()),
            Some("test-node".to_string()),
        )
        .await;
    assert!(matches!(result, IpcMessage::Created { .. }), "{result:?}");
}

/// Give `device` the certificate `primary_key` signs for it and "home", a
/// network it first joined with that certificate. Returns the certificate.
async fn hold_certificate(device: &Node, primary_key: &SecretKey) -> control::DeviceCert {
    let cert = control::DeviceCert::create(primary_key, &device.id(), 0);
    let daemon = device.daemon();
    let stored = cert.clone();
    let primary = primary_key.public();
    device
        .run(async move {
            identity::store_device_cert(&stored).unwrap();
            create(&daemon, "home").await;
            config::update_network("home", |net| {
                net.join_certificate_issuer = Some(primary);
                Ok(())
            })
            .unwrap();
        })
        .await;
    cert
}

/// Pair `device` with `primary` as a completed pairing leaves them: the device
/// holds the primary's certificate and a network joined with it, and the
/// primary coordinates "home" with the device on its roster as its own device,
/// named "phone". Returns the certificate.
async fn paired(primary: &Node, device: &Node) -> control::DeviceCert {
    let cert = hold_certificate(device, &primary.key).await;
    let daemon = primary.daemon();
    let member = cert.clone();
    let (primary_id, device_id) = (primary.id(), device.id());
    primary
        .run(async move {
            create(&daemon, "home").await;
            let handle = daemon.registry.networks.get("home").unwrap();
            let mut state = handle.state.write().unwrap();
            let template = state.members.all()[0].clone();
            state.members.add(Member {
                identity: device_id,
                is_coordinator: false,
                hostname: Some("phone".to_string()),
                user_identity: Some(primary_id),
                device_cert: Some(member),
                ..template
            });
        })
        .await;
    cert
}

fn waiting(cert: &control::DeviceCert) -> Vec<PendingUnpair> {
    vec![PendingUnpair {
        cert: cert.clone(),
        phase: UnpairPhase::Request,
    }]
}

fn revoked(cfg: &config::AppConfig, device: EndpointId) -> bool {
    config::revoked_device_ids(cfg).contains(&device)
}

/// A device that unpairs itself while its primary is offline keeps the request,
/// across a restart of its own, until the primary is back and confirms that it
/// saved the revocation, nullifier included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_primary_records_the_unpair_once_it_is_back() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    primary.stop().await;
    // Lookups fail at once while the primary is away, as for one never seen.
    relay.fail.store(true, Ordering::Relaxed);

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(device.cert().await, None);
    assert!(!device.has_network("home").await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    device.stop().await;
    device.start().await;
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    relay.fail.store(false, Ordering::Relaxed);
    primary.start().await;
    introduce(&device, &primary);
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert!(revoked(&primary.settings().await, device.id()));
    assert!(primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// The primary records an unpair asked for after its roster dropped the device,
/// as a departure processed by another coordinator leaves it: the certificate,
/// not the roster, shows the pairing (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_primary_records_an_unpair_after_its_roster_dropped_the_device() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    paired(&primary, &device).await;
    let daemon = primary.daemon();
    let device_id = device.id();
    primary
        .run(async move {
            let handle = daemon.registry.networks.get("home").unwrap();
            handle.state.write().unwrap().members.remove(&device_id);
        })
        .await;
    introduce(&device, &primary);

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    device
        .eventually("the primary to confirm", |cfg| {
            cfg.pending_unpairs.is_empty()
        })
        .await;
    assert!(revoked(&primary.settings().await, device.id()));
    assert!(primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// An unpair interrupted after it was saved, with the certificate still on
/// disk, is finished at the next start: the certificate and its networks go
/// before anything restores them, and the request is kept and sent, not taken
/// for a new pairing (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_during_cleanup_finishes_the_unpair() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    // As an unpair interrupted right after it was saved leaves the device,
    // which also knows where its primary is from earlier connections.
    let saved = cert.clone();
    let hint = primary.daemon().transport.endpoint.addr();
    device
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpairs.push(PendingUnpair {
                    cert: saved,
                    phase: UnpairPhase::Cleanup,
                });
                cfg.endpoint_hints = vec![hint];
                Ok(())
            })
            .unwrap();
        })
        .await;
    device.stop().await;

    device.start().await;
    // Gone before the daemon read the certificate, not just by now.
    assert_eq!(device.daemon().registry.device_cert, None);
    assert_eq!(device.cert().await, None);
    assert!(!device.has_network("home").await);
    assert!(!device.daemon().registry.networks.contains_key("home"));
    // Sent, not dropped: the primary has it.
    device
        .eventually("the primary to confirm", |cfg| {
            cfg.pending_unpairs.is_empty()
        })
        .await;
    assert!(revoked(&primary.settings().await, device.id()));
    device.stop().await;
    primary.stop().await;
}

/// A primary answers again for a revocation it already saved, so a device whose
/// answer was lost asks again safely, and keeps its request until it gets one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_confirmation_is_answered_again() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    relay.fail.store(true, Ordering::Relaxed);
    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    // The device's request reaches the primary, which records it, but the
    // answer is lost: the link drops before the device reads it.
    let link = dialer(device.key.clone()).await;
    let conn = link
        .connect(primary.daemon().transport.endpoint.addr(), PAIR_ALPN)
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    control::send_framed(
        &mut send,
        &control::PairMsg::UnpairRequest { cert: cert.clone() },
    )
    .await
    .unwrap();
    let device_id = device.id();
    primary
        .eventually("the revocation to be saved", move |cfg| {
            revoked(cfg, device_id)
        })
        .await;
    link.close().await;
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    relay.fail.store(false, Ordering::Relaxed);
    introduce(&device, &primary);
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    let revocations = primary.settings().await.revoked_devices;
    assert_eq!(revocations, [device.id().to_string()]);
    device.stop().await;
    primary.stop().await;
}

/// Pairing again with the same primary cancels the request, which would
/// otherwise revoke the new pairing, once the new certificate is saved. A
/// restart between the two cancels it too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_again_cancels_the_unpair_request() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    relay.fail.store(true, Ordering::Relaxed);
    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    relay.fail.store(false, Ordering::Relaxed);
    introduce(&device, &primary);
    let daemon = primary.daemon();
    let ticket = match primary.run(async move { daemon.start_pairing() }).await {
        IpcMessage::PairingTicket { ticket } => ticket,
        other => panic!("{other:?}"),
    };
    let (primary_id, secret) = control::decode_pairing_ticket(&ticket).unwrap();
    let daemon = device.daemon();
    let result = device
        .run(async move { daemon.pair_with_device(primary_id, secret.to_vec()).await })
        .await;
    assert!(
        matches!(result, IpcMessage::PairingComplete { .. }),
        "{result:?}"
    );
    assert_eq!(device.cert().await, Some(cert.clone()));
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert!(!device.attempt_requests().await);
    assert!(!revoked(&primary.settings().await, device.id()));

    // As a restart between saving the certificate and cancelling leaves it.
    let saved = waiting(&cert);
    device
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpairs = saved;
                Ok(())
            })
            .unwrap();
        })
        .await;
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert_eq!(device.cert().await, Some(cert.clone()));
    assert!(!revoked(&primary.settings().await, device.id()));

    // A notice that arrived before the new pairing completed, and was handled
    // after it, is not about the new pairing.
    let daemon = device.daemon();
    let primary_id = primary.id();
    device
        .run(async move {
            let before = daemon.registry.pairing_count.load(Ordering::Acquire) - 1;
            daemon.registry.on_unpaired_notice(primary_id, before).await;
        })
        .await;
    assert_eq!(device.cert().await, Some(cert));
    device.stop().await;
    primary.stop().await;
}

/// `ray unpair` of an offline device saves the revocation and the notice,
/// keeps the notice across the primary's restart, and tells the device once it
/// is back. The device cleans up and confirms, which ends the notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_device_is_told_once_it_is_back() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    paired(&primary, &device).await;
    device.stop().await;
    relay.fail.store(true, Ordering::Relaxed);

    let daemon = primary.daemon();
    let target = device.id().to_string();
    let result = primary
        .run(async move { daemon.unpair(&target).await })
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let settings = primary.settings().await;
    assert!(revoked(&settings, device.id()));
    assert_eq!(settings.pending_unpair_notices, [device.id()]);
    assert!(primary.nullifies("home", device.id()));
    primary.stop().await;
    primary.start().await;
    assert_eq!(
        primary.settings().await.pending_unpair_notices,
        [device.id()]
    );

    relay.fail.store(false, Ordering::Relaxed);
    device.start().await;
    assert!(device.cert().await.is_some());
    introduce(&primary, &device);
    introduce(&device, &primary);
    primary.daemon().registry.notice_nudge.notify_one();
    device
        .eventually("the device to finish its unpair", |cfg| {
            cfg.pending_unpairs.is_empty() && cfg.networks.is_empty()
        })
        .await;
    assert_eq!(device.cert().await, None);
    primary
        .eventually("the device to confirm", |cfg| {
            cfg.pending_unpair_notices.is_empty()
        })
        .await;
    device.stop().await;
    primary.stop().await;
}

/// Delivering `ControlMsg::Unpaired` does not end it: the notice stays until
/// the device confirms with its request, or until it pairs again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notice_stays_until_the_device_confirms_or_pairs_again() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let device_key = SecretKey::generate();
    let device_id = device_key.public();
    let cert = control::DeviceCert::create(&primary.key, &device_id, 0);
    // The device's end: it takes the notice, and never confirms on its own.
    let device = Endpoint::builder(presets::N0)
        .secret_key(device_key.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![transport::mesh_alpn()])
        .bind()
        .await
        .unwrap();
    let (notices, mut told) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let device = device.clone();
        async move {
            while let Some(incoming) = device.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let notices = notices.clone();
                tokio::spawn(async move {
                    while let Ok((_send, mut recv)) = conn.accept_bi().await {
                        if let Ok(control::FrameRead::Frame(frame)) =
                            control::recv_frame(&mut recv).await
                        {
                            let _ = notices.send(frame.msg);
                        }
                    }
                });
            }
        }
    });
    let daemon = primary.daemon();
    let member = cert.clone();
    let primary_id = primary.id();
    primary
        .run(async move {
            create(&daemon, "home").await;
            let handle = daemon.registry.networks.get("home").unwrap();
            let mut state = handle.state.write().unwrap();
            let template = state.members.all()[0].clone();
            state.members.add(Member {
                identity: device_id,
                is_coordinator: false,
                hostname: Some("phone".to_string()),
                user_identity: Some(primary_id),
                device_cert: Some(member),
                ..template
            });
        })
        .await;
    primary
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(device.addr());

    let daemon = primary.daemon();
    let target = device_id.to_string();
    let result = primary
        .run(async move { daemon.unpair(&target).await })
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let msg = tokio::time::timeout(Duration::from_secs(15), told.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(msg, ControlMsg::Unpaired), "{msg:?}");
    // Told again, with the attempt run to its end: still waiting.
    let daemon = primary.daemon();
    assert!(
        primary
            .run(async move { daemon.registry.attempt_unpair_notices().await })
            .await
    );
    let msg = tokio::time::timeout(Duration::from_secs(15), told.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(msg, ControlMsg::Unpaired), "{msg:?}");
    assert_eq!(primary.settings().await.pending_unpair_notices, [device_id]);

    let addr = primary.daemon().transport.endpoint.addr();
    let request = control::PairMsg::UnpairRequest { cert };
    let reply = exchange(&device_key, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert_eq!(primary.settings().await.pending_unpair_notices, []);

    // Told again, as after another `ray unpair`, then paired again.
    primary
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpair_notices.push(device_id);
                Ok(())
            })
            .unwrap();
        })
        .await;
    let daemon = primary.daemon();
    let ticket = match primary.run(async move { daemon.start_pairing() }).await {
        IpcMessage::PairingTicket { ticket } => ticket,
        other => panic!("{other:?}"),
    };
    let (_, secret) = control::decode_pairing_ticket(&ticket).unwrap();
    let request = control::PairMsg::Request {
        secret,
        device_pubkey: device_id,
    };
    let reply = exchange(&device_key, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::Response { .. })),
        "{reply:?}"
    );
    assert_eq!(primary.settings().await.pending_unpair_notices, []);
    accept.abort();
    device.close().await;
    primary.stop().await;
}

/// A request that reaches the primary is not enough: the device keeps it until
/// the primary answers that the revocation is saved (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_request_stays_pending() {
    let relay = Relay::start().await;
    let mut device = Node::new(&relay).await;
    device.start().await;
    let primary_key = SecretKey::generate();
    // The primary's end: it reads each request, then closes without an answer.
    let primary = Endpoint::builder(presets::N0)
        .secret_key(primary_key.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![PAIR_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let primary = primary.clone();
        async move {
            while let Some(incoming) = primary.accept().await {
                let Ok(conn) = incoming.await else { continue };
                if let Ok((_send, mut recv)) = conn.accept_bi().await
                    && let Ok(request) = control::recv_framed::<control::PairMsg>(&mut recv).await
                {
                    let _ = requests.send(request);
                }
                conn.close(VarInt::from_u32(0), b"no answer");
            }
        }
    });
    let cert = hold_certificate(&device, &primary_key).await;
    device
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(primary.addr());

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let request = tokio::time::timeout(Duration::from_secs(15), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(&request, control::PairMsg::UnpairRequest { cert: sent } if *sent == cert),
        "{request:?}"
    );
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    accept.abort();
    primary.close().await;
    device.stop().await;
}

/// A primary on pairing version 2 cannot record an unpair: the device sends it
/// the earlier `ControlMsg::RequestUnpair` and keeps its own request, which
/// that sends nothing back to confirm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_primary_gets_the_earlier_request_and_the_unpair_stays() {
    let relay = Relay::start().await;
    let mut device = Node::new(&relay).await;
    device.start().await;
    let primary_key = SecretKey::generate();
    let primary = Endpoint::builder(presets::N0)
        .secret_key(primary_key.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![PAIR_V2_ALPN.to_vec(), transport::mesh_alpn()])
        .bind()
        .await
        .unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let primary = primary.clone();
        async move {
            while let Some(incoming) = primary.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let requests = requests.clone();
                tokio::spawn(async move {
                    while let Ok((_send, mut recv)) = conn.accept_bi().await {
                        if let Ok(control::FrameRead::Frame(frame)) =
                            control::recv_frame(&mut recv).await
                        {
                            let _ = requests.send((conn.alpn().to_vec(), frame.msg));
                        }
                    }
                });
            }
        }
    });
    let cert = hold_certificate(&device, &primary_key).await;
    device
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(primary.addr());

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let (alpn, msg) = tokio::time::timeout(Duration::from_secs(15), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alpn, transport::mesh_alpn());
    assert!(matches!(msg, ControlMsg::RequestUnpair), "{msg:?}");
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    accept.abort();
    primary.close().await;
    device.stop().await;
}

/// A primary records an unpair only for a certificate it issued to the key
/// that asks, and only over pairing version 3. Version 2 still answers an
/// older device's network list request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_primary_refuses_an_unpair_it_cannot_verify() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let daemon = primary.daemon();
    primary
        .run(async move { create(&daemon, "home").await })
        .await;
    let device = SecretKey::generate();
    let stranger = SecretKey::generate();
    let ours = control::DeviceCert::create(&primary.key, &device.public(), 0);
    let addr = primary.daemon().transport.endpoint.addr();

    let list = control::PairMsg::NetworkListRequest { cert: ours.clone() };
    let reply = exchange(&device, &addr, PAIR_V2_ALPN, &list).await;
    assert!(
        matches!(reply, Some(control::PairMsg::NetworkListResponse { .. })),
        "{reply:?}"
    );
    let mut forged = control::DeviceCert::create(&stranger, &device.public(), 0);
    forged.user_identity = primary.id();
    for (cert, alpn) in [
        // Signed by someone else.
        (
            control::DeviceCert::create(&stranger, &device.public(), 0),
            PAIR_ALPN,
        ),
        // Names us, but someone else signed it.
        (forged, PAIR_ALPN),
        // Ours, for another key than the one asking.
        (
            control::DeviceCert::create(&primary.key, &stranger.public(), 0),
            PAIR_ALPN,
        ),
        // Over version 2.
        (ours.clone(), PAIR_V2_ALPN),
    ] {
        let request = control::PairMsg::UnpairRequest { cert };
        let reply = exchange(&device, &addr, alpn, &request).await;
        assert!(reply.is_none(), "{reply:?}");
    }
    assert_eq!(
        primary.settings().await.revoked_devices,
        Vec::<String>::new()
    );

    let request = control::PairMsg::UnpairRequest { cert: ours };
    let reply = exchange(&device, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert!(revoked(&primary.settings().await, device.public()));
    primary.stop().await;
}

/// An endpoint for `key` that only dials, without a relay. Bound like a
/// daemon's, so it reaches the addresses a daemon's endpoint lists.
async fn dialer(key: SecretKey) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

/// Send `msg` as `key` over `alpn` and return the answer, or `None` when the
/// other side closes without one.
async fn exchange(
    key: &SecretKey,
    addr: &iroh::EndpointAddr,
    alpn: &[u8],
    msg: &control::PairMsg,
) -> Option<control::PairMsg> {
    let endpoint = dialer(key.clone()).await;
    let reply = tokio::time::timeout(Duration::from_secs(15), async {
        let conn = endpoint.connect(addr.clone(), alpn).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        control::send_framed(&mut send, msg).await.unwrap();
        let reply = control::recv_framed(&mut recv).await.ok();
        conn.close(VarInt::from_u32(0), b"done");
        reply
    })
    .await
    .unwrap();
    endpoint.close().await;
    reply
}
