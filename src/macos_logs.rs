//! Unified logs for the native app, packet tunnel, and embedded Rust core.
//!
//! Read through Apple's log utility so retention and privacy rules stay with
//! macOS. The bundled CLI reads directly, including when the tunnel is down;
//! the embedded IPC server uses the same reader for standalone CLI clients.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdout, Command};
use tokio::task::JoinHandle;

pub const SUBSYSTEM: &str = "com.rayfish.app";

/// Own every subprocess for one request. Closing a pipe, quitting the pager,
/// disconnecting IPC, or cancelling the request also stops its live log reader.
pub struct LogReader {
    history: Option<LogProcess>,
    live: Option<LogProcess>,
}

impl LogReader {
    pub fn start(since: Option<Duration>, follow: bool) -> Result<Self> {
        // Subscribe before reading history so live events are buffered while
        // `log show` scans the store. The two sources can overlap at startup.
        let live = follow
            .then(|| LogProcess::spawn(&mut live_command()))
            .transpose()?;
        let history = Some(LogProcess::spawn(&mut history_command(since))?);
        Ok(Self { history, live })
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if let Some(history) = self.history.as_mut() {
            let n = history.read(buffer).await?;
            if n != 0 {
                return Ok(n);
            }
            self.history = None;
        }
        match self.live.as_mut() {
            Some(live) => live.read(buffer).await,
            None => Ok(0),
        }
    }
}

fn command(mode: &str) -> Command {
    let mut command = Command::new("/usr/bin/log");
    command.args([
        mode,
        "--style",
        "compact",
        "--color",
        "none",
        "--predicate",
        &format!("subsystem == \"{SUBSYSTEM}\""),
    ]);
    command
}

fn history_command(since: Option<Duration>) -> Command {
    let mut command = command("show");
    command.args(["--info", "--debug", "--no-pager"]);
    if let Some(since) = since {
        // The CLI accepts compound and subsecond durations; Apple's --last
        // accepts whole seconds. Round up rather than omit requested events.
        let seconds = since
            .as_secs()
            .saturating_add(u64::from(since.subsec_nanos() != 0));
        command.args(["--last", &format!("{seconds}s")]);
    } else {
        command.arg("--today");
    }
    command
}

fn live_command() -> Command {
    let mut command = command("stream");
    command.args(["--level", "debug"]);
    command
}

struct LogProcess {
    child: Child,
    stdout: ChildStdout,
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
}

impl LogProcess {
    fn spawn(command: &mut Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start macOS log reader")?;
        let stdout = child.stdout.take().context("open macOS log output")?;
        let stderr = child.stderr.take().context("open macOS log errors")?;
        let stderr = tokio::spawn(async move {
            let mut errors = Vec::new();
            stderr.take(8192).read_to_end(&mut errors).await?;
            Ok(errors)
        });
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let n = self.stdout.read(buffer).await.context("read macOS logs")?;
        if n == 0 {
            let status = self
                .child
                .wait()
                .await
                .context("wait for macOS log reader")?;
            if !status.success() {
                let errors = (&mut self.stderr)
                    .await
                    .context("read macOS log errors")??;
                anyhow::bail!(
                    "macOS log reader exited with {status}: {}",
                    String::from_utf8_lossy(&errors).trim()
                );
            }
        }
        Ok(n)
    }
}

impl Drop for LogProcess {
    fn drop(&mut self) {
        self.stderr.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn streams_output_and_reports_command_errors() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf 'first log\n'; printf 'access denied\n' >&2; exit 7",
        ]);
        let mut process = LogProcess::spawn(&mut command).unwrap();
        let mut buffer = [0; 128];
        let n = process.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..n], b"first log\n");
        let error = process.read(&mut buffer).await.unwrap_err();
        assert!(error.to_string().contains("access denied"));
        assert!(error.to_string().contains('7'));
    }

    #[tokio::test]
    async fn closing_reader_stops_an_idle_child() {
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let process = LogProcess::spawn(&mut command).unwrap();
        let pid = process.child.id().unwrap();
        drop(process);
        timeout(Duration::from_secs(2), async {
            loop {
                // Signal zero only checks whether this process still exists.
                if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
