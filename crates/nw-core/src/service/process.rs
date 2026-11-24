use super::{
    Client,
    auth::{Grant, Key, RpcRole},
};
use nw_ipc::Endpoint;
use std::{
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::process::{Child, ChildStdin};

pub(super) struct OwnedProcess {
    pub(super) child: Mutex<Child>,
    _lifetime: ChildStdin,
    kill_on_drop: bool,
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let child = self
                .child
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = child.start_kill();
        }
    }
}
struct StartingProcess(Option<Child>);
impl Drop for StartingProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.start_kill();
        }
    }
}
impl OwnedProcess {
    pub(super) fn confirms(&self, pid: u32) -> bool {
        self.child.lock().is_ok_and(|mut child| {
            child.try_wait().is_ok_and(|status| status.is_none())
                && child.id() == Some(pid)
                && child.try_wait().is_ok_and(|status| status.is_none())
        })
    }
}
pub struct ApiProcess {
    _process: Arc<OwnedProcess>,
}
pub(super) async fn launch(
    binary: &Path,
    arguments: &[&str],
    role: RpcRole,
    kill_on_drop: bool,
) -> Result<(Arc<OwnedProcess>, Grant), String> {
    if !binary.is_absolute() {
        return Err("invalid_runtime_binary".into());
    }
    let binary = binary
        .canonicalize()
        .map_err(|_| "runtime_component_missing")?;
    if !binary.is_file() {
        return Err("runtime_component_missing".into());
    }
    let key = Key::random()?;
    let mut command = tokio::process::Command::new(&binary);
    command
        .args(arguments)
        .current_dir(binary.parent().ok_or("invalid_runtime_binary")?)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    for name in [
        "SystemRoot",
        "WINDIR",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut starting = StartingProcess(Some(command.spawn().map_err(|_| "runtime_start_failed")?));
    let child = starting.0.as_mut().ok_or("runtime_start_failed")?;
    let pid = child.id().ok_or("runtime_start_failed")?;
    let mut lifetime = child.stdin.take().ok_or("ipc_bootstrap_failed")?;
    key.deliver(&mut lifetime, role).await?;
    // A failed bootstrap must always kill its child. Only the desktop-owned
    // core may outlive its owner to finish an explicitly permitted session tail.
    let child = starting.0.take().ok_or("runtime_start_failed")?;
    Ok((
        Arc::new(OwnedProcess {
            child: Mutex::new(child),
            _lifetime: lifetime,
            kill_on_drop,
        }),
        Grant { key, pid, role },
    ))
}
impl Client {
    pub async fn spawn_daemon(binary: &Path) -> Result<Self, String> {
        let paths = crate::config::Paths::discover().map_err(|_| "runtime_path_unavailable")?;
        let endpoint = Endpoint::new(paths.core_shadow, nw_proto::Lane::Shadow)
            .map_err(|error| error.to_string())?;
        let (process, grant) =
            launch(binary, &["--bootstrap-stdin"], RpcRole::Control, false).await?;
        Ok(Self::authorized(
            endpoint,
            grant,
            super::Peer::Child(process),
        ))
    }
}
impl super::Service {
    pub async fn spawn_api(&mut self, binary: &Path) -> Result<ApiProcess, String> {
        let (process, grant) = launch(binary, &["--bootstrap-stdin"], RpcRole::Api, true).await?;
        let access = Arc::get_mut(&mut self.access).ok_or("ipc_authorization_failed")?;
        if access
            .grants
            .iter()
            .any(|other| other.role == RpcRole::Api || other.pid == grant.pid)
        {
            return Err("ipc_authorization_failed".into());
        }
        access.grants.push(grant);
        Ok(ApiProcess { _process: process })
    }
}
