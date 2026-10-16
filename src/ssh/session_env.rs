//! Process setup shared by PTY and pipe SSH sessions.

use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Whether a client-controlled variable is safe to pass to a login session.
pub(super) fn env_accepted(name: &str) -> bool {
    matches!(name, "LANG" | "TZ" | "COLORTERM" | "TERM") || name.starts_with("LC_")
}

pub(super) fn login_program() -> Option<PathBuf> {
    if uzers::get_effective_uid() != 0 || std::env::var_os("RAYFISH_SSH_NO_LOGIN").is_some() {
        return None;
    }
    ["/bin/login", "/usr/bin/login"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| {
            std::fs::metadata(path)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

pub(super) fn tty_name(pts: &impl AsRawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 128];
    let result = unsafe { libc::ttyname_r(pts.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if result != 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

/// Build the `pre_exec` hook that switches the child to the session user.
///
/// The supplementary groups are resolved here, in the parent. The hook runs
/// between fork and exec in a multithreaded process, where an NSS lookup such
/// as `initgroups` can deadlock on a lock another thread held at fork time, so
/// the child only makes the raw set*id calls and checks they took effect.
pub(super) fn drop_privs(
    uid: u32,
    gid: u32,
    name: &str,
) -> Result<impl FnMut() -> std::io::Result<()> + Send + Sync + 'static> {
    let already_dropped =
        uid != 0 && unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == gid;
    let groups = if already_dropped {
        Vec::new()
    } else {
        let name = CString::new(name).context("user name contains NUL")?;
        group_list(&name, gid)?
    };
    Ok(move || {
        if already_dropped {
            return Ok(());
        }
        // SAFETY: only async-signal-safe syscalls on memory owned by the
        // closure; `groups` is not reallocated here.
        unsafe {
            if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::getuid() != uid
                || libc::geteuid() != uid
                || libc::getgid() != gid
                || libc::getegid() != gid
            {
                return Err(Error::from(ErrorKind::PermissionDenied));
            }
        }
        Ok(())
    })
}

/// The user's group list (primary group included), as `initgroups` would set.
fn group_list(name: &CStr, gid: u32) -> Result<Vec<libc::gid_t>> {
    // The kernel's NGROUPS_MAX on Linux; far beyond any real account.
    const MAX_GROUPS: usize = 65_536;
    let mut capacity = 64usize;
    loop {
        let mut count = capacity as libc::c_int;
        #[cfg(target_os = "macos")]
        let (result, mut groups) = {
            let mut groups = vec![0 as libc::c_int; capacity];
            // SAFETY: `groups` holds `count` entries and outlives the call.
            let result = unsafe {
                libc::getgrouplist(
                    name.as_ptr(),
                    gid as libc::c_int,
                    groups.as_mut_ptr(),
                    &mut count,
                )
            };
            let groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
            (result, groups)
        };
        #[cfg(not(target_os = "macos"))]
        let (result, mut groups) = {
            let mut groups = vec![0 as libc::gid_t; capacity];
            // SAFETY: `groups` holds `count` entries and outlives the call.
            let result =
                unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
            (result, groups)
        };
        if result >= 0 {
            groups.truncate(count.max(0) as usize);
            // macOS setgroups rejects more than NGROUPS_MAX (16) entries;
            // initgroups truncates the same way. The primary group is first.
            #[cfg(target_os = "macos")]
            groups.truncate(16);
            return Ok(groups);
        }
        drop(groups);
        anyhow::ensure!(
            capacity < MAX_GROUPS,
            "user is in more than {MAX_GROUPS} groups"
        );
        // glibc reports the size it needs; other libcs only say "too small".
        capacity = (count.max(0) as usize).max(capacity * 2).min(MAX_GROUPS);
    }
}

pub(super) fn login_env<'a>(
    home: &Path,
    shell: &Path,
    name: &str,
) -> [(&'a str, std::ffi::OsString); 5] {
    [
        ("HOME", home.into()),
        ("USER", name.into()),
        ("LOGNAME", name.into()),
        ("SHELL", shell.into()),
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_list_includes_the_primary_group() {
        let name = uzers::get_current_username().expect("test runs as a named user");
        let name = CString::new(name.into_encoded_bytes()).expect("user names have no NUL");
        let gid = uzers::get_current_gid();
        let groups = group_list(&name, gid).expect("group lookup succeeds");
        assert!(groups.contains(&gid));
    }
}
