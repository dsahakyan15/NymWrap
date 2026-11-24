//! The cover protocol is an allowlist. No shadow operation can be represented.
use nw_ipc::{Endpoint, IpcError, Listener, Packet};
use nw_proto::{DriftTask, Lane, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ExecutionToken(String);
impl ExecutionToken {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub id: u32,
    pub command: Command,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Tasks {},
    Complete {
        task: DriftTask,
    },
    BeginSearch {
        task: DriftTask,
    },
    FinishSearch {
        task: DriftTask,
        token: ExecutionToken,
    },
    ValidateSearch {
        task: DriftTask,
        token: ExecutionToken,
    },
    Pause {
        paused: bool,
    },
    SafetyStop {
        event_id: String,
        reason: StopReason,
    },
    Snapshot {
        snapshot: Snapshot,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Captcha,
    Login,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    YoutubeFeed,
    AdTopics,
    SearchSuggestions,
    AiMemory,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub kind: CaptureKind,
    pub captured_at: u64,
    pub items: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u16,
    pub id: u32,
    pub result: Result,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Result {
    Ack {},
    Execution {
        token: ExecutionToken,
    },
    Error {
        code: ErrorCode,
    },
    Status {
        paused: bool,
        mode: Mode,
        ai_web_automation: bool,
    },
    Tasks {
        tasks: Vec<DriftTask>,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Assisted,
    Extension,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AlreadyAttempted,
    RequestInProgress,
    WorkspaceLocked,
    NotReady,
    Paused,
    InvalidRequest,
    ModelUnavailable,
    StorageUnavailable,
}
impl Command {
    pub fn validate(&self) -> std::result::Result<(), IpcError> {
        let valid_text =
            |s: &str| !s.trim().is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control);
        match self {
            Self::FinishSearch { token, .. } | Self::ValidateSearch { token, .. }
                if token.as_str().len() != 64
                    || !token.as_str().bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Err(IpcError::Frame)
            }
            Self::SafetyStop { event_id, .. }
                if event_id.len() != 32
                    || !event_id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Err(IpcError::Frame)
            }
            Self::Complete { task }
            | Self::BeginSearch { task }
            | Self::ValidateSearch { task, .. }
            | Self::FinishSearch { task, .. }
                if task.plan_hash.len() != 64
                    || !task.plan_hash.bytes().all(|b| b.is_ascii_hexdigit())
                    || !(1..=30).contains(&task.stage)
                    || !(1..=30).contains(&task.day)
                    || task.action_index >= 10
                    || !valid_text(&task.text) =>
            {
                Err(IpcError::Frame)
            }
            Self::Snapshot { snapshot }
                if snapshot.items.is_empty()
                    || snapshot.items.len() > 30
                    || snapshot.items.iter().any(|s| !valid_text(s)) =>
            {
                Err(IpcError::Frame)
            }
            _ => Ok(()),
        }
    }
}
pub fn endpoint() -> std::result::Result<Endpoint, IpcError> {
    #[cfg(windows)]
    let value = { format!("nymwrap-{}-core-cover", nw_ipc::user_namespace()?) };
    #[cfg(unix)]
    let value = {
        use std::path::PathBuf;
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/share")))
            .ok_or(IpcError::Endpoint)?
            .join("nymwrap");
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data.join("runtime"))
            .join("nymwrap/core-cover.sock")
            .to_string_lossy()
            .into_owned()
    };
    Endpoint::new(value, Lane::Cover)
}
pub async fn call(endpoint: &Endpoint, request: Request) -> std::result::Result<Reply, IpcError> {
    if endpoint.lane() != Lane::Cover
        || request.version != nw_proto::SCHEMA_VERSION
        || request.id == 0
    {
        return Err(IpcError::Lane);
    }
    request.command.validate()?;
    let mut stream = endpoint.connect().await?;
    nw_ipc::write_packet(
        &mut stream,
        &Packet::new(Lane::Cover, u64::from(request.id), request.command),
        Lane::Cover,
    )
    .await?;
    let response: Packet<Result> = nw_ipc::read_packet(&mut stream, Lane::Cover).await?;
    if response.request_id != u64::from(request.id) {
        return Err(IpcError::Frame);
    }
    Ok(Reply {
        version: nw_proto::SCHEMA_VERSION,
        id: request.id,
        result: response.body,
    })
}
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Command) -> impl Future<Output = Result> + Send;
}
pub async fn serve<H: Handler>(listener: Listener, handler: H) -> std::io::Result<()> {
    if listener.lane() != Lane::Cover {
        return Err(std::io::Error::other("ipc_wrong_lane"));
    }
    let handler = Arc::new(handler);
    let permits = Arc::new(Semaphore::new(8));
    loop {
        let mut stream = listener.accept().await.map_err(std::io::Error::other)?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(packet) = nw_ipc::read_packet::<Command, _>(&mut stream, Lane::Cover).await
            else {
                return;
            };
            if packet.request_id == 0
                || packet.request_id > u64::from(u32::MAX)
                || packet.body.validate().is_err()
            {
                return;
            }
            let result = handler.handle(packet.body).await;
            let _ = nw_ipc::write_packet(
                &mut stream,
                &Packet::new(Lane::Cover, packet.request_id, result),
                Lane::Cover,
            )
            .await;
        });
    }
}
pub fn read_native<R: std::io::Read>(input: &mut R) -> std::io::Result<Option<Request>> {
    let mut header = [0u8; 4];
    let first = input.read(&mut header[..1])?;
    if first == 0 {
        return Ok(None);
    }
    input.read_exact(&mut header[1..])?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("invalid_native_frame"));
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; size]);
    input.read_exact(&mut bytes)?;
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| std::io::Error::other("invalid_native_request"))?;
    if request.version != nw_proto::SCHEMA_VERSION
        || request.id == 0
        || request.command.validate().is_err()
    {
        return Err(std::io::Error::other("invalid_native_request"));
    }
    Ok(Some(request))
}
pub fn write_native<W: std::io::Write>(output: &mut W, reply: &Reply) -> std::io::Result<()> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(reply).map_err(|_| std::io::Error::other("invalid_native_reply"))?,
    );
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("invalid_native_reply"));
    }
    output.write_all(&(bytes.len() as u32).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Cover;
    impl Handler for Cover {
        async fn handle(&self, _: Command) -> Result {
            Result::Ack {}
        }
    }
    #[test]
    fn native_protocol_cannot_name_shadow_operations() {
        for command in [
            serde_json::json!({"kind":"vault"}),
            serde_json::json!({"kind":"status","shadow_history":[]}),
            serde_json::json!({"kind":"snapshot","snapshot":{"kind":"youtube_feed","captured_at":0,"items":[],"persona":[]}}),
            serde_json::json!({"kind":"safety_stop","event_id":"a".repeat(32),"reason":"captcha","url":"SYNTHETIC_SHADOW_CANARY"}),
            serde_json::json!({"kind":"safety_stop","event_id":"a".repeat(32),"reason":"execute"}),
            serde_json::json!({"kind":"safety_stop","event_id":"not_an_id","reason":"login"}),
        ] {
            let bytes =
                serde_json::to_vec(&serde_json::json!({"version":1,"id":1,"command":command}))
                    .unwrap();
            let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
            frame.extend(bytes);
            assert!(read_native(&mut frame.as_slice()).is_err());
        }
        assert!(read_native(&mut u32::MAX.to_le_bytes().as_slice()).is_err());
    }
    #[tokio::test]
    async fn actual_cover_endpoint_is_lane_bound() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let address = format!("nymwrap-cover-test-{}", std::process::id());
        #[cfg(unix)]
        let address = dir
            .path()
            .join("private/cover.sock")
            .to_string_lossy()
            .into_owned();
        let _keep = dir;
        let endpoint = Endpoint::new(address, Lane::Cover).unwrap();
        let listener = Listener::bind(endpoint.clone()).unwrap();
        let server = tokio::spawn(serve(listener, Cover));
        let response = call(
            &endpoint,
            Request {
                version: 1,
                id: 7,
                command: Command::Tasks {},
            },
        )
        .await
        .unwrap();
        assert!(matches!(response.result, Result::Ack {}));
        server.abort();
        let _ = server.await;
    }
}
