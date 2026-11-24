//! Child ownership and authenticated private IPC. No TCP sockets or HTTP connector.
use crate::{
    ShapedRequest,
    wire::{Command as EgressCommand, Envelope, MAX_WIRE, Request, Response, SessionKey},
};
use nw_ipc::Endpoint;
use rand::{RngCore, rngs::OsRng};
#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, sync::Mutex};
use zeroize::Zeroizing;
struct Child {
    process: tokio::process::Child,
    _lifetime: tokio::process::ChildStdin,
    key: SessionKey,
    sequence: u64,
    endpoint: Endpoint,
    #[cfg(not(target_os = "linux"))]
    binary: PathBuf,
}
pub struct Client {
    child: Mutex<Option<Child>>,
}
impl Client {
    pub async fn spawn(binary: &Path, endpoint: Endpoint) -> Result<Self, &'static str> {
        if endpoint.lane() != nw_proto::Lane::Shadow || !binary.is_absolute() {
            return Err("invalid_egress_configuration");
        }
        let binary = binary
            .canonicalize()
            .map_err(|_| "transport_component_missing")?;
        let mut command = tokio::process::Command::new(&binary);
        command.args(["--socket", endpoint.value()]).env_clear();
        for name in [
            "SystemRoot",
            "WINDIR",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
            "HOME",
            "TEMP",
            "TMP",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        Self::spawn_prepared(command, endpoint).await
    }
    /// Trusted launchers may prepare namespace/identity setup and fixed fixture
    /// arguments. The program must already be canonical and absolute. Authority
    /// still belongs to our retained child; no existing PID can be attached.
    /// Bootstrap stdin and output sinks are always replaced here, never supplied
    /// by the caller. The ordinary spawn() keeps its minimal environment policy.
    pub async fn spawn_prepared(
        mut command: tokio::process::Command,
        endpoint: Endpoint,
    ) -> Result<Self, &'static str> {
        let program = Path::new(command.as_std().get_program());
        if endpoint.lane() != nw_proto::Lane::Shadow || !program.is_absolute() {
            return Err("invalid_egress_configuration");
        }
        let binary = program
            .canonicalize()
            .map_err(|_| "transport_component_missing")?;
        if program != binary || !binary.is_file() {
            return Err("invalid_egress_configuration");
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut process = command.spawn().map_err(|_| "transport_start_failed")?;
        let mut lifetime = process.stdin.take().ok_or("transport_start_failed")?;
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(&mut *bytes);
        let key = SessionKey::new(*bytes).map_err(|_| "memory_lock_failed")?;
        lifetime
            .write_all(&*bytes)
            .await
            .map_err(|_| "transport_start_failed")?;
        lifetime
            .flush()
            .await
            .map_err(|_| "transport_start_failed")?;
        Ok(Self {
            child: Mutex::new(Some(Child {
                process,
                _lifetime: lifetime,
                key,
                sequence: 0,
                endpoint,
                #[cfg(not(target_os = "linux"))]
                binary,
            })),
        })
    }
    pub async fn send(
        &self,
        conversation: &str,
        request: &ShapedRequest,
        authorization: &str,
    ) -> Result<String, &'static str> {
        self.send_request(conversation, request, authorization, false)
            .await
    }
    pub async fn send_once(
        &self,
        conversation: &str,
        request: &ShapedRequest,
        authorization: &str,
    ) -> Result<String, &'static str> {
        self.send_request(conversation, request, authorization, true)
            .await
    }
    async fn send_request(
        &self,
        conversation: &str,
        request: &ShapedRequest,
        authorization: &str,
        ephemeral: bool,
    ) -> Result<String, &'static str> {
        let value = Request {
            conversation: conversation.into(),
            body: request.bytes().to_vec(),
            authorization: authorization.into(),
        };
        let command = if ephemeral {
            EgressCommand::SendOnce { request: value }
        } else {
            EgressCommand::Send { request: value }
        };
        match self.exchange(command).await? {
            Response::Answer { ref mut text } => Ok(std::mem::take(text)),
            Response::Error { .. } => Err("remote_request_failed"),
            _ => Err("invalid_egress_message"),
        }
    }
    pub async fn initialize(
        &self,
        state: &Path,
        host: &str,
        path: &str,
    ) -> Result<(), &'static str> {
        self.initialize_with_bridges(state, host, path, None).await
    }
    pub async fn initialize_with_bridges(
        &self,
        state: &Path,
        host: &str,
        path: &str,
        bridges: Option<crate::bridges::BridgeConfig>,
    ) -> Result<(), &'static str> {
        if let Some(bridges) = &bridges {
            bridges.validate()?;
        }
        if !state.is_absolute() {
            return Err("invalid_egress_configuration");
        }
        match self
            .exchange(EgressCommand::Initialize {
                state: state.to_str().ok_or("invalid_egress_configuration")?.into(),
                host: host.into(),
                path: path.into(),
                bridges,
            })
            .await?
        {
            Response::Ready {} => Ok(()),
            _ => Err("transport_initialization_failed"),
        }
    }
    pub async fn reset(&self) -> Result<(), &'static str> {
        match self.exchange(EgressCommand::Reset {}).await? {
            Response::Ready {} => Ok(()),
            _ => Err("transport_reset_failed"),
        }
    }
    async fn exchange(&self, value: EgressCommand) -> Result<Response, &'static str> {
        let mut guard = self.child.lock().await;
        let mut child = guard.take().ok_or("transport_stopped")?;
        let result = child.exchange(value).await;
        if result.is_ok() {
            *guard = Some(child);
        } // Cancellation/authentication failure stops the child, never replays a send.
        result
    }
}
impl Child {
    async fn exchange(&mut self, value: EgressCommand) -> Result<Response, &'static str> {
        let timeout = if matches!(value, EgressCommand::Initialize { .. }) {
            Duration::from_secs(190)
        } else {
            Duration::from_secs(130)
        };
        let start = tokio::time::Instant::now();
        let mut stream = loop {
            if self
                .process
                .try_wait()
                .map_err(|_| "transport_stopped")?
                .is_some()
            {
                return Err("transport_stopped");
            }
            match self.endpoint.connect().await {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() < Duration::from_secs(15) => {
                    tokio::time::sleep(Duration::from_millis(100)).await
                }
                Err(_) => return Err("transport_bootstrap_timeout"),
            }
        };
        if nw_ipc::peer_process(&stream).map_err(|_| "ipc_wrong_peer")?
            != self.process.id().ok_or("transport_stopped")?
        {
            return Err("ipc_wrong_peer");
        }
        #[cfg(not(target_os = "linux"))]
        if nw_platform::process_image(self.process.id().ok_or("transport_stopped")?)
            .and_then(|p| p.canonicalize())
            .map_err(|_| "ipc_wrong_peer")?
            != self.binary
        {
            return Err("ipc_wrong_peer");
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("egress_sequence_exhausted")?;
        let envelope = self.key.seal(self.sequence, &value)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| "invalid_egress_message")?);
        nw_ipc::write_frame(&mut stream, &bytes, MAX_WIRE * 5)
            .await
            .map_err(|_| "transport_send_uncertain")?;
        let bytes = nw_ipc::read_frame_timeout(&mut stream, MAX_WIRE * 5, timeout)
            .await
            .map_err(|_| "transport_send_uncertain")?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| "invalid_egress_message")?;
        self.key.open(&envelope, self.sequence)
    }
}
