//! Process-wide instance selection, fixed before config, logging or IPC starts.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

pub struct UserInstance {
    pub directory: PathBuf,
    pub runtime: PathBuf,
    pub owner_uid: u32,
}

static USER_INSTANCE: OnceLock<UserInstance> = OnceLock::new();

pub fn user_instance() -> Option<&'static UserInstance> {
    USER_INSTANCE.get()
}

pub fn is_rootless() -> bool {
    user_instance().is_some()
}

#[cfg(all(target_os = "linux", feature = "desktop"))]
pub fn select_rootless() -> anyhow::Result<()> {
    use anyhow::Context;
    let uid = uzers::get_effective_uid();
    anyhow::ensure!(
        uid != 0 && uid == uzers::get_current_uid(),
        "rootless mode must run as a regular user, without sudo"
    );
    let directory = std::env::var_os("RAYFISH_ROOTLESS_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::data_local_dir().map(|path| path.join("rayfish/rootless")))
        .context("could not determine the rootless state directory")?;
    anyhow::ensure!(
        directory.is_absolute(),
        "RAYFISH_ROOTLESS_DIR must be an absolute path"
    );
    let runtime = match std::env::var_os("RAYFISH_ROOTLESS_DIR") {
        Some(value) if !value.is_empty() => directory.join("run"),
        _ => dirs::runtime_dir()
            .map(|path| path.join("rayfish-rootless"))
            .unwrap_or_else(|| directory.join("run")),
    };
    crate::ipc::set_socket_path(runtime.join("rayfish.sock"))?;
    USER_INSTANCE
        .set(UserInstance {
            directory,
            runtime,
            owner_uid: uid,
        })
        .map_err(|_| anyhow::anyhow!("instance already selected"))
}

#[cfg(unix)]
pub fn ensure_private_dir(path: &Path, owner_uid: u32) -> anyhow::Result<()> {
    use std::fs::{DirBuilder, symlink_metadata};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.try_exists()? {
        DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    let metadata = symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "instance directory must be a real directory"
    );
    anyhow::ensure!(
        metadata.uid() == owner_uid && metadata.mode() & 0o077 == 0,
        "instance directory must be owned by the current user with mode 0700"
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn private_directories_reject_shared_or_symlink_paths() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private");
        let uid = fs::metadata(temp.path()).unwrap();
        use std::os::unix::fs::MetadataExt;
        ensure_private_dir(&path, uid.uid()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_private_dir(&path, uid.uid()).is_err());
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(ensure_private_dir(&link, uid.uid()).is_err());
        assert!(ensure_private_dir(temp.path(), uid.uid().wrapping_add(1)).is_err());
    }
}
