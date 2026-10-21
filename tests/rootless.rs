//! Real unprivileged daemon lifecycle, private IPC and CLI instance selection.
#![cfg(all(target_os = "linux", feature = "desktop"))]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use ray_proto::ipc::{self, IpcMessage};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const RAY: &str = env!("CARGO_BIN_EXE_ray");

fn command(directory: &Path) -> Command {
    let mut command = Command::new(RAY);
    command
        .env("RAYFISH_ROOTLESS_DIR", directory)
        .env("RUST_LOG", "rayfish=info")
        .env_remove("RAYFISH_CONFIG_DIR")
        .kill_on_drop(true);
    command
}

struct Running {
    child: Child,
    logs: JoinHandle<()>,
    socks: String,
}

async fn start(directory: &Path) -> Running {
    let mut child = command(directory)
        .args(["rootless", "--socks5", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let (ready, waiting) = oneshot::channel();
    let logs = tokio::spawn(async move {
        let mut ready = Some(ready);
        let mut address = None;
        while let Some(line) = lines.next_line().await.unwrap() {
            if line.contains("rootless SOCKS5 listening") {
                address = line
                    .split("address=")
                    .nth(1)
                    .map(|value| value.split_whitespace().next().unwrap().to_owned());
            }
            if line.contains("rootless userspace networking ready")
                && let Some(ready) = ready.take()
            {
                ready
                    .send(address.take().expect("SOCKS address precedes readiness"))
                    .unwrap();
            }
        }
    });
    let socks = timeout(Duration::from_secs(30), waiting)
        .await
        .unwrap()
        .unwrap();
    Running { child, logs, socks }
}

async fn cli(directory: &Path, args: &[&str]) -> Output {
    timeout(
        Duration::from_secs(15),
        command(directory).arg("--rootless").args(args).output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn request(directory: &Path, message: IpcMessage) -> IpcMessage {
    let stream = UnixStream::connect(directory.join("run/rayfish.sock"))
        .await
        .unwrap();
    let mut framed = ipc::framed(stream);
    ipc::send(&mut framed, message).await.unwrap();
    timeout(Duration::from_secs(10), ipc::recv(&mut framed))
        .await
        .unwrap()
        .unwrap()
}

async fn stop(mut running: Running, directory: &Path) {
    let output = cli(directory, &["stop"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        timeout(Duration::from_secs(15), running.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    running.logs.await.unwrap();
    assert!(!directory.join("run/rayfish.sock").exists());
}

#[tokio::test]
async fn independent_rootless_instances_have_private_state_and_safe_lifecycle() {
    if uzers::get_effective_uid() == 0 {
        eprintln!("rootless lifecycle test requires an unprivileged test user");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let first_path = temporary.path().join("first");
    let second_path = temporary.path().join("second");
    let missing_path = temporary.path().join("missing");
    let missing = cli(&missing_path, &["status", "--json"]).await;
    assert!(String::from_utf8_lossy(&missing.stdout).contains("daemon not running"));
    assert!(!missing_path.exists(), "a CLI read must not create state");
    let first = start(&first_path).await;
    let second = start(&second_path).await;
    for path in [&first_path, &second_path] {
        for private in [path.to_path_buf(), path.join("run"), path.join("logs")] {
            let metadata = std::fs::metadata(private).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), uzers::get_effective_uid());
        }
        for private in [path.join("run/rayfish.sock"), path.join("proxy-password")] {
            assert_eq!(
                std::fs::metadata(private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let first_status = cli(&first_path, &["status", "--json"]).await;
    assert!(first_status.status.success());
    let first_status: serde_json::Value = serde_json::from_slice(&first_status.stdout).unwrap();
    let second_status = cli(&second_path, &["status", "--json"]).await;
    let second_status: serde_json::Value = serde_json::from_slice(&second_status.stdout).unwrap();
    assert_eq!(first_status["rootless"], true);
    assert_ne!(first_status["endpoint"], second_status["endpoint"]);
    let duplicate = timeout(
        Duration::from_secs(15),
        command(&first_path).arg("rootless").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already running"));
    let mut socks = TcpStream::connect(&first.socks).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x05ff);
    let password = std::fs::read(first_path.join("proxy-password")).unwrap();
    let mut socks = TcpStream::connect(&first.socks).await.unwrap();
    socks.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x0502);
    socks
        .write_all(&[
            1,
            3,
            b'r',
            b'a',
            b'y',
            u8::try_from(password.len()).unwrap(),
        ])
        .await
        .unwrap();
    socks.write_all(&password).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x0100);
    // An IPv4 CONNECT request is explicitly rejected, never sent over the host network.
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut reply = [0; 22];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 8);
    assert!(matches!(
        request(&first_path, IpcMessage::Down).await,
        IpcMessage::Ok { .. }
    ));
    assert!(matches!(
        request(&first_path, IpcMessage::Up { hostname: None }).await,
        IpcMessage::Ok { .. }
    ));
    assert!(matches!(
        request(
            &first_path,
            IpcMessage::ExitNodeUse {
                network: "mesh".into(),
                peer: Some("peer".into())
            }
        )
        .await,
        IpcMessage::Error { .. }
    ));
    stop(first, &first_path).await;
    assert!(
        cli(&second_path, &["status", "--json"])
            .await
            .status
            .success()
    );
    let mut crashed = start(&first_path).await;
    crashed.child.start_kill().unwrap();
    crashed.child.wait().await.unwrap();
    crashed.logs.await.unwrap();
    assert!(first_path.join("run/rayfish.sock").exists());
    assert!(
        cli(&second_path, &["status", "--json"])
            .await
            .status
            .success()
    );
    let restarted = start(&first_path).await;
    let status = cli(&first_path, &["status", "--json"]).await;
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["endpoint"], first_status["endpoint"]);
    assert_ne!(
        std::fs::read(first_path.join("proxy-password")).unwrap(),
        password
    );
    stop(restarted, &first_path).await;
    stop(second, &second_path).await;
}
