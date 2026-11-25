//! Privileged setup only; no sudo, helper installation or host-network fallback.
use crate::client::Client;
use nw_ipc::Endpoint;
use nw_platform::ChildIdentity;
use std::{fs::File, path::Path};

/// Created before the runtime, while the administrative coordinator still has
/// permission to enter the provisioned transport namespace. Never accepts text
/// from a model, RPC, workspace or imported file.
pub struct LinuxNamespace {
    namespace: File,
    identity: Option<ChildIdentity>,
}
impl LinuxNamespace {
    pub fn prepare(namespace: &Path, uid: u32, gid: u32) -> Result<Self, &'static str> {
        if !namespace.is_absolute() {
            return Err("invalid_network_namespace");
        }
        let identity = ChildIdentity::new(uid, gid).map_err(|_| "invalid_network_identity")?;
        let namespace = File::open(namespace).map_err(|_| "network_namespace_unavailable")?;
        nw_platform::isolate_core_network(&namespace).map_err(|_| "core_namespace_failed")?;
        Ok(Self {
            namespace,
            identity: Some(identity),
        })
    }

    pub async fn spawn(self, binary: &Path, endpoint: Endpoint) -> Result<Client, &'static str> {
        let command = Client::command(binary, &endpoint);
        self.spawn_command(command, endpoint).await
    }

    async fn spawn_command(
        mut self,
        command: Result<tokio::process::Command, &'static str>,
        endpoint: Endpoint,
    ) -> Result<Client, &'static str> {
        let result = async {
            let mut command = command?;
            nw_platform::enter_child_network_namespace(
                command.as_std_mut(),
                &self.namespace,
                self.identity.ok_or("identity_drop_failed")?,
            )
            .map_err(|_| "transport_namespace_failed")?;
            Client::spawn_prepared(command, endpoint).await
        }
        .await;
        // Also drop on a missing binary, invalid command or failed exec. Any
        // failure here is fatal to the coordinator; callers must propagate it.
        self.seal();
        result
    }

    fn seal(&mut self) {
        if let Some(identity) = self.identity.take() {
            // Cancellation and early return must not leave a privileged caller
            // processing data. A failed irreversible transition is process-fatal.
            if nw_platform::drop_process_identity(identity).is_err()
                || nw_platform::deny_remote_sockets().is_err()
            {
                std::process::abort();
            }
        }
    }
}
impl Drop for LinuxNamespace {
    fn drop(&mut self) {
        self.seal();
    }
}
