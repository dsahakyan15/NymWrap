//! Small audited OS boundary. Everything outside `sys` remains safe Rust.
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::{
    collections::BTreeMap,
    io,
    sync::{LazyLock, Mutex},
};
use zeroize::Zeroize;
#[allow(unsafe_code)]
mod sys;
#[cfg(any(windows, test))]
mod wlan;
#[cfg(unix)]
pub use sys::current_group_id;
pub use sys::inherited_stdin_pipe;
#[cfg(target_os = "macos")]
pub use sys::local_peer_process;
pub use sys::open_device_config;
#[cfg(target_os = "linux")]
pub use sys::{
    ChildIdentity, drop_process_identity, enter_child_network_namespace, isolate_core_network,
};
#[cfg(target_os = "linux")]
pub use sys::{SandboxIdentity, confine_leaf_daemon, sandbox_leaf_filter, sandbox_status_stream};
#[cfg(target_os = "macos")]
pub use sys::{confine_device_probe, inherited_probe_file, macos_probe_command};
#[cfg(target_os = "linux")]
pub use sys::{confine_import_worker, deny_remote_sockets};
pub use sys::{current_user_id, harden_process, process_image};
pub use sys::{
    device_browser_policy, device_home_paths, device_host_names, device_ip_addresses,
    device_mac_addresses, device_machine_ids, device_policy_hints, device_timezones,
    device_user_names, device_wifi_inventory, device_wifi_ssids,
};
#[derive(Default)]
pub struct HygienePolicyHints {
    pub location_disabled: Option<bool>,
    pub llmnr_disabled: Option<bool>,
    pub netbios_disabled: Option<bool>,
    pub mdns_disabled: Option<bool>,
    /// Kernel synchronization error estimate, not an NTP-enabled setting.
    pub clock_within_bounds: Option<bool>,
}
#[cfg(target_os = "linux")]
pub use sys::{sandbox_data_files, sandbox_read_files};
/// Only kernel-verified per-directory encryption is accepted for transport state.
pub fn encrypted_directory(path: &std::path::Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::other("invalid_encrypted_directory"));
    }
    let mut ancestor = Some(path);
    while let Some(p) = ancestor {
        match std::fs::symlink_metadata(p) {
            Ok(m) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        return Err(io::Error::other("invalid_encrypted_directory"));
                    }
                }
                if m.is_symlink() || !m.is_dir() {
                    return Err(io::Error::other("invalid_encrypted_directory"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        ancestor = p.parent();
    }
    #[cfg(windows)]
    {
        create_private_directory_all(path)?;
        private_directory(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    sys::verify_directory_encryption(path)
}
#[cfg(windows)]
pub use sys::{
    AppContainerProcess, SandboxOutput, appcontainer_daemon, appcontainer_exchange,
    appcontainer_exchange_with_files, appcontainer_pipe_acl, appcontainer_pipe_address,
    appcontainer_probe_exchange, inherited_read_file, is_appcontainer, verify_lpac_boundary,
};
#[cfg(windows)]
pub use sys::{kernel_object_owner, private_directory};

/// Create missing directories with the current user as owner from the outset.
/// Existing directories never have their owner changed.
#[cfg(windows)]
pub fn create_private_directory_all(path: &std::path::Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(io::Error::other("invalid_private_directory"));
    }
    let mut missing = vec![];
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.is_dir() && meta.file_attributes() & 0x400 == 0 => {}
            Ok(_) => return Err(io::Error::other("invalid_private_directory")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(ancestor),
            Err(e) => return Err(e),
        }
    }
    for directory in missing.into_iter().rev() {
        sys::create_private_directory(directory)?;
    }
    private_directory(path)
}
#[cfg(unix)]
pub fn create_private_directory_all(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.is_absolute() {
        return Err(io::Error::other("invalid_private_directory"));
    }
    for ancestor in path.ancestors() {
        if let Ok(meta) = std::fs::symlink_metadata(ancestor)
            && (!meta.is_dir() || meta.file_type().is_symlink())
        {
            return Err(io::Error::other("invalid_private_directory"));
        }
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.mode() & 0o077 != 0 || meta.uid().to_string() != current_user_id()? {
        return Err(io::Error::other("invalid_private_directory"));
    }
    Ok(())
}

static LOCKS: LazyLock<Mutex<BTreeMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
#[cfg(any(windows, target_os = "linux", test))]
fn all_observed_true(values: &[Option<bool>]) -> Option<bool> {
    if values.contains(&Some(false)) {
        Some(false)
    } else if !values.is_empty() && values.iter().all(|value| *value == Some(true)) {
        Some(true)
    } else {
        None
    }
}
struct Guard {
    pages: Vec<usize>,
}
impl Guard {
    fn new(bytes: &[u8]) -> io::Result<Self> {
        let size = sys::page_size()?;
        let start = bytes.as_ptr() as usize;
        let first = start / size * size;
        let last = start
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("memory_lock_failed"))?
            .div_ceil(size)
            * size;
        let mut locks = LOCKS
            .lock()
            .map_err(|_| io::Error::other("memory_lock_failed"))?;
        let mut pages = vec![];
        for page in (first..last).step_by(size) {
            if let Some(count) = locks.get_mut(&page) {
                *count += 1;
            } else if let Err(error) = sys::lock_page(page, size) {
                for previous in pages {
                    release(&mut locks, previous, size);
                }
                return Err(error);
            } else {
                locks.insert(page, 1);
            }
            pages.push(page);
        }
        Ok(Self { pages })
    }
}
fn release(locks: &mut BTreeMap<usize, usize>, page: usize, size: usize) {
    if let Some(count) = locks.get_mut(&page) {
        *count -= 1;
        if *count == 0 {
            locks.remove(&page);
            sys::unlock_page(page, size);
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let (Ok(mut locks), Ok(size)) = (LOCKS.lock(), sys::page_size()) {
            for page in &self.pages {
                release(&mut locks, *page, size);
            }
        }
    }
}
/// Shared-page reference counts prevent dropping one key from unlocking its neighbors.
pub struct LockedKey {
    _guard: Guard,
    secret: SecretBox<[u8; 32]>,
}
impl LockedKey {
    pub fn new(secret: SecretBox<[u8; 32]>) -> io::Result<Self> {
        let guard = Guard::new(secret.expose_secret())?;
        Ok(Self {
            _guard: guard,
            secret,
        })
    }
    pub fn copy(&self) -> io::Result<Self> {
        Self::new(SecretBox::new(Box::new(*self.expose_secret())))
    }
}
impl ExposeSecret<[u8; 32]> for LockedKey {
    fn expose_secret(&self) -> &[u8; 32] {
        self.secret.expose_secret()
    }
}
impl Drop for LockedKey {
    fn drop(&mut self) {
        self.secret.expose_secret_mut().zeroize();
    }
}
/// Fixed-size string allocation, locked until after its contents are zeroized.
pub struct LockedString {
    _guard: Guard,
    secret: SecretString,
}
impl LockedString {
    pub fn new(secret: SecretString) -> io::Result<Self> {
        let guard = Guard::new(secret.expose_secret().as_bytes())?;
        Ok(Self {
            _guard: guard,
            secret,
        })
    }
}
impl ExposeSecret<str> for LockedString {
    fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }
}
impl AsRef<[u8]> for LockedString {
    fn as_ref(&self) -> &[u8] {
        self.expose_secret().as_bytes()
    }
}
impl Drop for LockedString {
    fn drop(&mut self) {
        self.secret.expose_secret_mut().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_or_absent_profile_settings_do_not_confirm_mac_randomization() {
        assert_eq!(all_observed_true(&[]), None);
        assert_eq!(all_observed_true(&[Some(true), None]), None);
        assert_eq!(all_observed_true(&[None, Some(false)]), Some(false));
        assert_eq!(all_observed_true(&[Some(true), Some(true)]), Some(true));
    }
    #[cfg(windows)]
    #[test]
    fn explicit_owner_directory_creation_rejects_existing_files_and_relative_paths() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("private/deep");
        create_private_directory_all(&root).unwrap();
        private_directory(&root).unwrap();
        private_directory(root.parent().unwrap()).unwrap();
        // An existing directory is validated, not recreated or adopted.
        create_private_directory_all(&root).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"SYNTHETIC_DIRECTORY_CANARY").unwrap();
        assert!(create_private_directory_all(&file).is_err());
        assert!(create_private_directory_all(&file.join("child")).is_err());
        assert!(create_private_directory_all(std::path::Path::new("relative")).is_err());
    }
    #[test]
    fn keys_are_locked_and_independent_drops_retain_other_locks() {
        let key = LockedKey::new(SecretBox::new(Box::new([73; 32]))).unwrap();
        let clone = key.copy().unwrap();
        let pages = clone._guard.pages.clone();
        drop(key);
        {
            let locks = LOCKS.lock().unwrap();
            assert!(pages.iter().all(|p| locks.get(p).is_some_and(|n| *n > 0)));
        }
        assert_eq!(clone.expose_secret(), &[73; 32]);
    }
    #[test]
    fn user_identity_is_available() {
        assert!(!current_user_id().unwrap().is_empty());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_denies_ip_sockets_but_keeps_private_ipc() {
        if std::env::var_os("NYMWRAP_SECCOMP_TEST").is_some() {
            deny_remote_sockets().unwrap();
            assert_eq!(
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(
                std::net::UdpSocket::bind("[::1]:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            std::os::unix::net::UnixStream::pair().unwrap();
            return;
        }
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::seccomp_denies_ip_sockets_but_keeps_private_ipc"
                ])
                .env("NYMWRAP_SECCOMP_TEST", "1")
                .status()
                .unwrap()
                .success()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_covers_existing_and_future_threads() {
        if std::env::var_os("NYMWRAP_SECCOMP_THREADS_TEST").is_none() {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "tests::seccomp_covers_existing_and_future_threads"
                    ])
                    .env("NYMWRAP_SECCOMP_THREADS_TEST", "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        // A positive control rules out a guest/container whose networking was absent already.
        std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let denied = || {
            assert_eq!(
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(
                std::net::UdpSocket::bind("[::1]:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            std::os::unix::net::UnixStream::pair().unwrap();
        };
        let (send, receive) = std::sync::mpsc::channel();
        let existing = std::thread::spawn(move || {
            receive.recv().unwrap();
            denied();
        });
        deny_remote_sockets().unwrap();
        send.send(()).unwrap();
        existing.join().unwrap();
        std::thread::spawn(denied).join().unwrap();
    }
}
