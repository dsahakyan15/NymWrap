//! Fresh native LPAC per inference; the supervisor never links native GGUF code.
use crate::{Message, ModelError, OutputSchema};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Probe {},
    Complete {
        messages: Vec<Message>,
        max_tokens: u32,
        schema: Option<OutputSchema>,
    },
    Embed {
        texts: Vec<String>,
    },
}
impl Drop for Command {
    fn drop(&mut self) {
        if let Self::Embed { texts } = self {
            texts.zeroize();
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Ready {},
    Text {
        content: String,
    },
    Vectors {
        values: Vec<Vec<f64>>,
        model_sha256: String,
        recipe_id: String,
    },
    Failed {
        kind: Failure,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    Invalid,
    TooLarge,
    Hash,
    Load,
    Inference,
    Timeout,
}
impl Drop for Reply {
    fn drop(&mut self) {
        match self {
            Self::Text { content } => content.zeroize(),
            Self::Vectors { values, .. } => values.zeroize(),
            _ => {}
        }
    }
}

pub struct WindowsModel {
    binary: PathBuf,
    paths: [PathBuf; 2],
    hashes: [String; 2],
    _files: [File; 2],
    gate: tokio::sync::Mutex<()>,
    waiting: tokio::sync::Semaphore,
    closed: tokio::sync::watch::Sender<bool>,
}
fn opened(path: &Path) -> Result<File, ModelError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| ModelError::Unavailable)?;
    if !path.is_absolute()
        || !meta.is_file()
        || meta.file_attributes() & 0x400 != 0
        || !(32..=64u64 * 1024 * 1024 * 1024).contains(&meta.len())
    {
        return Err(ModelError::Invalid);
    }
    OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .map_err(|_| ModelError::Unavailable)
}
impl WindowsModel {
    pub async fn load(
        binary: &Path,
        chat: &Path,
        chat_hash: &str,
        embedding: &Path,
        embedding_hash: &str,
    ) -> Result<Self, ModelError> {
        if [chat_hash, embedding_hash]
            .iter()
            .any(|hash| hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ModelError::Invalid);
        }
        let worker = Self {
            binary: binary.to_owned(),
            paths: [chat.to_owned(), embedding.to_owned()],
            hashes: [
                chat_hash.to_ascii_lowercase(),
                embedding_hash.to_ascii_lowercase(),
            ],
            _files: [opened(chat)?, opened(embedding)?],
            gate: tokio::sync::Mutex::new(()),
            waiting: tokio::sync::Semaphore::new(8),
            closed: tokio::sync::watch::channel(false).0,
        };
        if !matches!(
            worker.exchange(Command::Probe {}, false).await?,
            Reply::Ready {}
        ) {
            return Err(ModelError::Unavailable);
        }
        Ok(worker)
    }
    /// Session ownership is separate from in-flight calls: locking the workspace
    /// cancels them even while they temporarily hold an Arc to this template.
    pub fn stop(&self) {
        self.closed.send_replace(true);
    }
    async fn exchange(&self, command: Command, background: bool) -> Result<Reply, ModelError> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return Err(ModelError::Unavailable);
        }
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(240), self.perform(command, background)) => result.map_err(|_| ModelError::Timeout)?,
            _ = closed.changed() => Err(ModelError::Unavailable),
        }
    }
    async fn perform(&self, command: Command, background: bool) -> Result<Reply, ModelError> {
        let _waiting = self
            .waiting
            .try_acquire()
            .map_err(|_| ModelError::Unavailable)?;
        let _gate = if background {
            self.gate.try_lock().map_err(|_| ModelError::Unavailable)?
        } else {
            tokio::time::timeout(Duration::from_secs(110), self.gate.lock())
                .await
                .map_err(|_| ModelError::Unavailable)?
        };
        if *self.closed.borrow() {
            return Err(ModelError::Unavailable);
        }
        let mut child = nw_sandbox::daemon::Launch {
            profile: nw_sandbox::daemon::Profile::Model,
            binary: self.binary.clone(),
            arguments: vec![
                "--worker-stdio".into(),
                "--chat-handle".into(),
                "@handle:chat".into(),
                "--embed-handle".into(),
                "@handle:embedding".into(),
                "--sha256".into(),
                self.hashes[0].clone().into(),
                "--embed-sha256".into(),
                self.hashes[1].clone().into(),
            ],
            listener: None,
            upstream: vec![],
            files: vec![
                ("chat".into(), self.paths[0].clone()),
                ("embedding".into(), self.paths[1].clone()),
            ],
            environment: vec![],
        }
        .spawn()
        .await
        .map_err(|_| ModelError::Unavailable)?;
        let json = Zeroizing::new(
            serde_json::to_vec(&nw_ipc::Packet::new(nw_proto::Lane::Shadow, 1, command))
                .map_err(|_| ModelError::Invalid)?,
        );
        if json.len() > nw_proto::MAX_FRAME_BYTES {
            return Err(ModelError::TooLarge);
        }
        let mut input = child.stdin.take().ok_or(ModelError::Unavailable)?;
        input
            .write_u32_le(json.len() as u32)
            .await
            .map_err(|_| ModelError::Unavailable)?;
        input
            .write_all(&json)
            .await
            .map_err(|_| ModelError::Unavailable)?;
        input.flush().await.map_err(|_| ModelError::Unavailable)?;
        drop(input);
        const LIMIT: usize = 4 * 1024 * 1024;
        let mut bytes = Zeroizing::new(Vec::new());
        child
            .stdout
            .take()
            .ok_or(ModelError::Unavailable)?
            .take((LIMIT + 5) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| ModelError::Unavailable)?;
        if bytes.len() < 4
            || bytes.len() > LIMIT + 4
            || !child
                .wait()
                .await
                .map_err(|_| ModelError::Unavailable)?
                .success()
        {
            return Err(ModelError::Unavailable);
        }
        let length =
            u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ModelError::Invalid)?) as usize;
        if length == 0 || length + 4 != bytes.len() {
            return Err(ModelError::Invalid);
        }
        let reply: nw_ipc::Packet<Reply> =
            serde_json::from_slice(&bytes[4..]).map_err(|_| ModelError::Invalid)?;
        if reply.version != nw_proto::SCHEMA_VERSION
            || reply.lane != nw_proto::Lane::Shadow
            || reply.request_id != 1
        {
            return Err(ModelError::Invalid);
        }
        if let Reply::Failed { kind } = &reply.body {
            return Err(match kind {
                Failure::TooLarge => ModelError::TooLarge,
                Failure::Timeout => ModelError::Timeout,
                Failure::Invalid => ModelError::Invalid,
                _ => ModelError::Unavailable,
            });
        }
        Ok(reply.body)
    }
    pub(crate) async fn post(
        &self,
        path: &str,
        value: serde_json::Value,
        background: bool,
    ) -> Result<serde_json::Value, ModelError> {
        let command = if path == "/v1/chat/completions" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                model: String,
                messages: Vec<Message>,
                max_tokens: u32,
                temperature: f64,
                stream: bool,
                #[serde(default)]
                nw_output_schema: Option<OutputSchema>,
            }
            let request: Request =
                serde_json::from_value(value).map_err(|_| ModelError::Invalid)?;
            if request.model != "default" || request.temperature != 0.0 || request.stream {
                return Err(ModelError::Invalid);
            }
            Command::Complete {
                messages: request.messages,
                max_tokens: request.max_tokens,
                schema: request.nw_output_schema,
            }
        } else if path == "/v1/embeddings" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                model: String,
                input: Vec<String>,
            }
            let request: Request =
                serde_json::from_value(value).map_err(|_| ModelError::Invalid)?;
            if !["nomic-embed-text", "local-embedding"].contains(&request.model.as_str()) {
                return Err(ModelError::Invalid);
            }
            Command::Embed {
                texts: request.input,
            }
        } else {
            return Err(ModelError::Invalid);
        };
        match &mut self.exchange(command, background).await? {
            Reply::Text { content } => Ok(
                serde_json::json!({"choices":[{"message":{"role":"assistant","content":std::mem::take(content)}}]}),
            ),
            Reply::Vectors {
                values,
                model_sha256,
                recipe_id,
            } => {
                if *model_sha256 != self.hashes[1]
                    || crate::embedding::for_model(model_sha256)
                        .is_none_or(|r| r.id != recipe_id.as_str())
                {
                    return Err(ModelError::Invalid);
                }
                Ok(
                    serde_json::json!({"data":std::mem::take(values).into_iter().enumerate().map(|(index,embedding)|serde_json::json!({"index":index,"embedding":embedding})).collect::<Vec<_>>(),"nw_model_sha256":model_sha256,"nw_embedding_recipe":recipe_id}),
                )
            }
            _ => Err(ModelError::Invalid),
        }
    }
}
