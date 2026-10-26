//! Unix-socket work for forwarding, done as the login account.
//!
//! The daemon is root, and on a unix socket the filesystem is the access
//! control: a root `connect` ignores it, and the listening service reads the
//! caller's uid with `SO_PEERCRED` and sees 0. Checking permissions first and
//! then acting as root is a race (the path can be swapped for a symlink in
//! between) and still hands the service the wrong uid. So each operation runs
//! in a short-lived forked child that has already become the login account,
//! and a socket it opens comes back to the daemon over a socketpair.
//!
//! The child lives between fork and `_exit` in a multithreaded process, so it
//! only makes raw syscalls on memory prepared before the fork, the same rule
//! as the session `pre_exec` hook in [`super::session_env`].

use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};

use super::login::LoginInfo;
use super::session_env::drop_privs;

/// Pending connections a reverse-forwarded socket queues, as sshd's.
const LISTEN_BACKLOG: libc::c_int = 128;

#[derive(Clone, Copy)]
enum Op {
    Connect,
    Listen,
    RemoveSocket,
    CreateDir,
    RemoveDir,
}

/// Dial the unix socket at `path` as `info`'s account.
pub(super) async fn connect(info: Arc<LoginInfo>, path: PathBuf) -> Result<UnixStream> {
    let fd = run_blocking(info, path, Op::Connect)
        .await?
        .context("the helper returned no socket")?;
    Ok(UnixStream::from_std(StdUnixStream::from(fd))?)
}

/// Bind and listen on `path` as `info`'s account. A stale socket the account
/// owns at that path is replaced; anything else there is an error.
pub(super) async fn listen(info: Arc<LoginInfo>, path: PathBuf) -> Result<UnixListener> {
    let fd = run_blocking(info, path, Op::Listen)
        .await?
        .context("the helper returned no socket")?;
    Ok(UnixListener::from_std(StdUnixListener::from(fd))?)
}

/// Remove the socket at `path` as `info`'s account. Not a socket, or already
/// gone, is left alone.
pub(super) async fn remove_socket(info: Arc<LoginInfo>, path: PathBuf) -> Result<()> {
    run_blocking(info, path, Op::RemoveSocket).await.map(drop)
}

/// Create a mode 0700 directory at `path` as `info`'s account. Fails if
/// anything already exists there.
pub(super) async fn create_dir(info: Arc<LoginInfo>, path: PathBuf) -> Result<()> {
    run_blocking(info, path, Op::CreateDir).await.map(drop)
}

/// Remove the empty directory at `path` as `info`'s account.
pub(super) async fn remove_dir(info: Arc<LoginInfo>, path: PathBuf) -> Result<()> {
    run_blocking(info, path, Op::RemoveDir).await.map(drop)
}

async fn run_blocking(info: Arc<LoginInfo>, path: PathBuf, op: Op) -> Result<Option<OwnedFd>> {
    let shown = path.display().to_string();
    tokio::task::spawn_blocking(move || run(&info, &path, op))
        .await
        .context("socket helper task failed")?
        .with_context(|| format!("{shown} as the login account"))
}

/// Fork, become the account, do `op`, and collect its result.
fn run(info: &LoginInfo, path: &Path, op: Op) -> Result<Option<OwnedFd>> {
    let mut become_user = drop_privs(info.uid, info.gid, &info.name)?;
    let c_path = CString::new(path.as_os_str().as_bytes()).context("path contains NUL")?;
    let addr = match op {
        Op::Connect | Op::Listen => Some(SocketAddr::new(&c_path)?),
        Op::RemoveSocket | Op::CreateDir | Op::RemoveDir => None,
    };
    let (parent_end, child_end) =
        StdUnixStream::pair().context("creating the helper socketpair")?;

    // SAFETY: the child runs only `child`, which makes async-signal-safe
    // syscalls on memory set up above and ends in `_exit`, never returning
    // into code that could take a lock another thread held at fork time.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::last_os_error()).context("forking the socket helper");
    }
    if pid == 0 {
        let errno = match become_user() {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().unwrap_or(libc::EPERM),
        };
        child(errno, op, &c_path, addr.as_ref(), child_end.as_raw_fd());
    }
    drop(child_end);
    let answer = receive(parent_end.as_raw_fd());
    reap(pid);
    let Answer { errno, fd } = answer?;
    if errno != 0 {
        return Err(Error::from_raw_os_error(errno).into());
    }
    Ok(fd)
}

/// The forked child. Never returns.
fn child(
    errno: libc::c_int,
    op: Op,
    path: &CString,
    addr: Option<&SocketAddr>,
    report: RawFd,
) -> ! {
    if errno != 0 {
        send(report, errno, None);
    }
    // SAFETY: plain syscalls on `path` and `addr`, both valid for the call.
    unsafe {
        let p = path.as_ptr();
        let result: Result<Option<RawFd>, libc::c_int> = match (op, addr) {
            (Op::Connect, Some(addr)) => open_socket().and_then(|fd| {
                let rc = libc::connect(fd, addr.as_ptr(), addr.len);
                if rc == 0 || errno_now() == libc::EINPROGRESS {
                    Ok(Some(fd))
                } else {
                    Err(errno_now())
                }
            }),
            (Op::Listen, Some(addr)) => {
                let mut st: libc::stat = zeroed();
                if libc::lstat(p, &mut st) == 0
                    && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
                    && st.st_uid == libc::getuid()
                {
                    libc::unlink(p);
                }
                libc::umask(0o177);
                open_socket().and_then(|fd| {
                    if libc::bind(fd, addr.as_ptr(), addr.len) == 0
                        && libc::listen(fd, LISTEN_BACKLOG) == 0
                    {
                        Ok(Some(fd))
                    } else {
                        Err(errno_now())
                    }
                })
            }
            (Op::RemoveSocket, _) => {
                let mut st: libc::stat = zeroed();
                if libc::lstat(p, &mut st) == 0
                    && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
                    && libc::unlink(p) != 0
                {
                    Err(errno_now())
                } else {
                    Ok(None)
                }
            }
            (Op::CreateDir, _) => {
                libc::umask(0o077);
                if libc::mkdir(p, 0o700) == 0 {
                    Ok(None)
                } else {
                    Err(errno_now())
                }
            }
            (Op::RemoveDir, _) => {
                if libc::rmdir(p) == 0 {
                    Ok(None)
                } else {
                    Err(errno_now())
                }
            }
            (Op::Connect | Op::Listen, None) => Err(libc::EINVAL),
        };
        match result {
            Ok(fd) => send(report, 0, fd),
            Err(errno) => send(report, errno, None),
        }
    }
}

/// A nonblocking, close-on-exec unix stream socket, ready for tokio.
///
/// # Safety
/// Only raw syscalls; safe to call in the forked child.
unsafe fn open_socket() -> Result<RawFd, libc::c_int> {
    // SAFETY: plain syscalls on an fd this function owns.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(errno_now());
        }
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) != 0
            || libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) != 0
        {
            return Err(errno_now());
        }
        Ok(fd)
    }
}

fn errno_now() -> libc::c_int {
    Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// Send the result to the daemon and exit. Uses stack memory only.
fn send(report: RawFd, errno: libc::c_int, fd: Option<RawFd>) -> ! {
    // SAFETY: the message, iovec and control buffer all live on this stack
    // frame for the duration of `sendmsg`; `_exit` skips every destructor.
    unsafe {
        let mut payload = errno.to_ne_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0u64; 4];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            libc::CMSG_DATA(cmsg).cast::<RawFd>().write_unaligned(fd);
        }
        let code = if libc::sendmsg(report, &msg, 0) < 0 {
            1
        } else {
            0
        };
        libc::_exit(code)
    }
}

struct Answer {
    errno: libc::c_int,
    fd: Option<OwnedFd>,
}

/// Read the child's answer: an errno, and the socket when there is one.
fn receive(report: RawFd) -> Result<Answer> {
    let mut payload = [0u8; size_of::<libc::c_int>()];
    let mut control = [0u64; 4];
    // SAFETY: the buffers outlive `recvmsg`, and a received fd is owned by
    // this process from then on, so wrapping it in `OwnedFd` is sound.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 4]>() as _;
        let n = loop {
            let n = libc::recvmsg(report, &mut msg, 0);
            if n >= 0 || errno_now() != libc::EINTR {
                break n;
            }
        };
        if n < 0 {
            return Err(Error::last_os_error()).context("reading the socket helper's answer");
        }
        let mut fd = None;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let raw = libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned();
            fd = Some(OwnedFd::from_raw_fd(raw));
        }
        if n as usize != payload.len() {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "the socket helper died",
            ))
            .context("reading the socket helper's answer");
        }
        Ok(Answer {
            errno: libc::c_int::from_ne_bytes(payload),
            fd,
        })
    }
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: waits on our own child; EINTR is retried.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 && errno_now() == libc::EINTR {}
}

/// A `sockaddr_un` built before the fork.
struct SocketAddr {
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl SocketAddr {
    fn new(path: &CString) -> Result<Self> {
        // SAFETY: an all-zero sockaddr_un is a valid empty address.
        let mut addr: libc::sockaddr_un = unsafe { zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_bytes_with_nul();
        if bytes.len() > addr.sun_path.len() {
            return Err(Error::from_raw_os_error(libc::ENAMETOOLONG).into());
        }
        for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        let offset = size_of::<libc::sockaddr_un>() - addr.sun_path.len();
        let len = libc::socklen_t::try_from(offset + bytes.len()).context("socket address")?;
        Ok(Self { addr, len })
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        (&self.addr as *const libc::sockaddr_un).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Arc<LoginInfo> {
        let name = uzers::get_current_username().expect("a passwd entry");
        Arc::new(super::super::login::resolve_login(&name.to_string_lossy()).expect("login"))
    }

    #[tokio::test]
    async fn listen_connect_and_clean_up() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sub = dir.path().join("private");
        create_dir(me(), sub.clone()).await.expect("create dir");
        let path = sub.join("s.sock");
        let listener = listen(me(), path.clone()).await.expect("listen");
        let _client = connect(me(), path.clone()).await.expect("connect");
        let (accepted, _) = listener.accept().await.expect("accept");
        let cred = accepted.peer_cred().expect("peer credentials");
        assert_ne!(cred.pid(), Some(std::process::id() as i32));

        remove_socket(me(), path.clone())
            .await
            .expect("remove socket");
        assert!(!path.exists());
        remove_dir(me(), sub.clone()).await.expect("remove dir");
        assert!(!sub.exists());
    }

    #[tokio::test]
    async fn connect_reports_the_kernels_refusal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let err = connect(me(), dir.path().join("missing.sock"))
            .await
            .expect_err("nothing listens there");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn listen_never_replaces_a_file_that_is_not_a_socket() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("plain");
        std::fs::write(&path, b"keep").expect("write file");
        listen(me(), path.clone())
            .await
            .expect_err("a file is in the way");
        remove_socket(me(), path.clone())
            .await
            .expect("not a socket is fine");
        assert_eq!(std::fs::read(&path).expect("read"), b"keep");
    }
}
