//! The daemon's open-file limit.
//!
//! Every peer connection, IPC client and transfer costs descriptors, and the
//! usual soft limit of 1024 is reached long before the hard limit. The daemon
//! raises its soft limit at startup and remembers the original, so the user
//! shells mesh SSH spawns get the limit a login would give them: a soft limit
//! above 1024 breaks programs that still pass descriptors to `select(2)`.

use std::io::Error;
use std::sync::OnceLock;

/// Upper bound for the raised soft limit, however high the hard limit is.
const NOFILE_CEILING: libc::rlim_t = 65_536;

static ORIGINAL: OnceLock<libc::rlimit> = OnceLock::new();

/// The soft limit to ask for: the hard limit, capped at [`NOFILE_CEILING`],
/// never below the current soft limit.
fn raised_soft(current: libc::rlimit) -> libc::rlim_t {
    current.rlim_max.min(NOFILE_CEILING).max(current.rlim_cur)
}

/// Raise the soft `RLIMIT_NOFILE` toward the hard limit. Best effort: on
/// failure the daemon keeps running with the limit it was given.
pub fn raise_nofile_limit() {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit into memory we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
        return;
    }
    let _ = ORIGINAL.set(current);
    let raised = libc::rlimit {
        rlim_cur: raised_soft(current),
        rlim_max: current.rlim_max,
    };
    if raised.rlim_cur == current.rlim_cur {
        return;
    }
    // SAFETY: setrlimit reads one rlimit from memory we own.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        let error = Error::last_os_error();
        tracing::debug!(%error, "could not raise the open-file limit");
        return;
    }
    tracing::debug!(
        from = current.rlim_cur,
        to = raised.rlim_cur,
        "raised the open-file limit"
    );
}

/// Put back the limit the daemon started with. Called between fork and exec,
/// so it only makes the one async-signal-safe syscall.
pub fn restore_nofile_limit() -> Result<(), Error> {
    let Some(original) = ORIGINAL.get() else {
        return Ok(());
    };
    // SAFETY: setrlimit reads one rlimit from memory that lives for the process.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, original) } != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(cur: libc::rlim_t, max: libc::rlim_t) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: cur,
            rlim_max: max,
        }
    }

    #[test]
    fn raises_to_the_hard_limit_under_the_ceiling() {
        assert_eq!(raised_soft(limit(1024, 4096)), 4096);
        assert_eq!(raised_soft(limit(1024, 524_288)), NOFILE_CEILING);
        assert_eq!(
            raised_soft(limit(1024, libc::RLIM_INFINITY)),
            NOFILE_CEILING
        );
    }

    #[test]
    fn never_lowers_the_soft_limit() {
        assert_eq!(raised_soft(limit(100_000, 200_000)), 100_000);
    }
}
