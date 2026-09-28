//! Keep Rust diagnostics beside the Swift app and tunnel logs in Console.

use std::sync::Once;

use tracing_oslog::OsLogger;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

static INIT: Once = Once::new();

pub(super) fn init() {
    // A process can construct several nodes across tunnel restarts. Install the
    // subscriber before creating the runtime so startup failures are logged too.
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,rayfish=debug,ray_apple=debug"));
        if let Err(error) = tracing_subscriber::registry()
            .with(filter)
            .with(OsLogger::new(rayfish::macos_logs::SUBSYSTEM, "core"))
            .try_init()
        {
            eprintln!("could not initialize Rayfish logging: {error}");
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rayfish::macos_logs::LogReader;
    use tokio::time::{interval, timeout};

    #[tokio::test]
    async fn core_events_reach_the_app_log_reader() {
        super::init();
        super::init();
        let marker = format!("ray-apple log probe {}", std::process::id());
        let mut reader = LogReader::start(Some(Duration::from_secs(1)), true).unwrap();
        let mut buffer = [0; 8192];
        let mut output = String::new();
        let mut emit = interval(Duration::from_millis(200));
        timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    // Repetition covers the log utility's subscription startup.
                    _ = emit.tick() => tracing::warn!(probe = %marker, "Apple core log probe"),
                    read = reader.read(&mut buffer) => {
                        let n = read.unwrap();
                        assert_ne!(n, 0, "live log reader stopped");
                        output.push_str(&String::from_utf8_lossy(&buffer[..n]));
                        if output.contains(&marker) {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("Rust core event did not reach unified logging");
    }
}
