//! Windows broker: native GGUF parsing and inference run in one-shot offline LPACs.
use crate::{
    Error, Inference,
    inference::{Cpu, verified_file},
    valid_chat, valid_texts, valid_vectors,
};
use nw_ipc::Packet;
use nw_llm::{Message, OutputSchema};
use nw_proto::{Lane, MAX_FRAME_BYTES, MAX_TEXT_BYTES, SCHEMA_VERSION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Invalid,
    TooLarge,
    Hash,
    Load,
    Inference,
    Timeout,
}
impl From<Error> for FailureKind {
    fn from(error: Error) -> Self {
        match error {
            Error::Invalid => Self::Invalid,
            Error::TooLarge => Self::TooLarge,
            Error::Hash => Self::Hash,
            Error::Load => Self::Load,
            Error::Inference => Self::Inference,
            Error::Timeout => Self::Timeout,
        }
    }
}
impl From<FailureKind> for Error {
    fn from(kind: FailureKind) -> Self {
        match kind {
            FailureKind::Invalid => Self::Invalid,
            FailureKind::TooLarge => Self::TooLarge,
            FailureKind::Hash => Self::Hash,
            FailureKind::Load => Self::Load,
            FailureKind::Inference => Self::Inference,
            FailureKind::Timeout => Self::Timeout,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
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
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Ready {},
    Text { content: String },
    Vectors { values: Vec<Vec<f64>> },
    Failed { kind: FailureKind },
}
impl Drop for Reply {
    fn drop(&mut self) {
        match self {
            Self::Text { content } => content.zeroize(),
            Self::Vectors { values } => values.zeroize(),
            _ => {}
        }
    }
}
fn encode<T: Serialize>(body: T, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let json = Zeroizing::new(
        serde_json::to_vec(&Packet::new(Lane::Shadow, 1, body)).map_err(|_| Error::Invalid)?,
    );
    if json.is_empty() || json.len() > limit {
        return Err(Error::TooLarge);
    }
    let mut framed = Zeroizing::new(Vec::with_capacity(json.len() + 4));
    framed.extend_from_slice(&(json.len() as u32).to_le_bytes());
    framed.extend_from_slice(&json);
    Ok(framed)
}
fn decode<T: DeserializeOwned>(mut reader: impl Read, limit: usize) -> Result<T, Error> {
    let mut length = [0; 4];
    reader.read_exact(&mut length).map_err(|_| Error::Invalid)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > limit {
        return Err(Error::TooLarge);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes).map_err(|_| Error::Invalid)?;
    if reader.read(&mut [0]).map_err(|_| Error::Invalid)? != 0 {
        return Err(Error::Invalid);
    }
    let packet: Packet<T> = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if packet.version != SCHEMA_VERSION || packet.lane != Lane::Shadow || packet.request_id != 1 {
        return Err(Error::Invalid);
    }
    Ok(packet.body)
}
/// The broker retains read-sharing handles, never parses GGUF or falls back to native inference.
pub struct Isolated {
    program: PathBuf,
    files: [File; 2],
    hashes: [String; 2],
}
impl Isolated {
    pub fn load(
        chat: &Path,
        chat_hash: &str,
        embedding: &Path,
        embedding_hash: &str,
    ) -> Result<Self, Error> {
        let (chat, _) = verified_file(chat, chat_hash)?;
        let (embedding, _) = verified_file(embedding, embedding_hash)?;
        let worker = Self {
            program: std::env::current_exe().map_err(|_| Error::Load)?,
            files: [chat, embedding],
            hashes: [chat_hash.into(), embedding_hash.into()],
        };
        if !matches!(worker.exchange(Command::Probe {})?, Reply::Ready {}) {
            return Err(Error::Load);
        }
        Ok(worker)
    }
    fn exchange(&self, command: Command) -> Result<Reply, Error> {
        let input = encode(command, MAX_FRAME_BYTES)?;
        let output = nw_platform::appcontainer_exchange_with_files(
            &self.program,
            &[
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
            &[("chat", &self.files[0]), ("embedding", &self.files[1])],
            input,
            OUTPUT_LIMIT + 4,
            Duration::from_secs(240),
            8 * 1024 * 1024 * 1024,
        )
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut => Error::Timeout,
            _ => Error::Inference,
        })?;
        if output.exit_code != 0 {
            return Err(Error::Inference);
        }
        decode(output.stdout.as_slice(), OUTPUT_LIMIT)
    }
}
impl Inference for Isolated {
    fn embedding_sha256(&self) -> Option<&str> {
        Some(&self.hashes[1])
    }
    fn complete(&mut self, messages: &[Message], max_tokens: u32) -> Result<String, Error> {
        self.complete_structured(messages, max_tokens, None)
    }
    fn complete_structured(
        &mut self,
        messages: &[Message],
        max_tokens: u32,
        schema: Option<OutputSchema>,
    ) -> Result<String, Error> {
        if !valid_chat(messages, max_tokens) {
            return Err(Error::Invalid);
        }
        match &mut self.exchange(Command::Complete {
            messages: messages.to_vec(),
            max_tokens,
            schema,
        })? {
            Reply::Text { content }
                if !content.trim().is_empty()
                    && content.len() <= MAX_TEXT_BYTES
                    && !content.contains('\0') =>
            {
                Ok(std::mem::take(content))
            }
            Reply::Failed { kind } => Err((*kind).into()),
            _ => Err(Error::Inference),
        }
    }
    fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error> {
        if !valid_texts(texts) {
            return Err(Error::Invalid);
        }
        match &mut self.exchange(Command::Embed {
            texts: texts.to_vec(),
        })? {
            Reply::Vectors { values } if valid_vectors(values, texts.len()) => {
                Ok(std::mem::take(values))
            }
            Reply::Failed { kind } => Err((*kind).into()),
            _ => Err(Error::Inference),
        }
    }
}
/// Synchronous entry point: no Winsock/Tokio runtime is initialized inside LPAC.
pub fn worker(
    chat_handle: usize,
    chat_hash: &str,
    embed_handle: usize,
    embed_hash: &str,
) -> Result<(), Error> {
    if !nw_platform::is_appcontainer().map_err(|_| Error::Load)? {
        return Err(Error::Invalid);
    }
    let command: Command = decode(std::io::stdin().lock(), MAX_FRAME_BYTES)?;
    match &command {
        Command::Complete {
            messages,
            max_tokens,
            ..
        } if !valid_chat(messages, *max_tokens) => return Err(Error::Invalid),
        Command::Embed { texts } if !valid_texts(texts) => return Err(Error::Invalid),
        _ => {}
    }
    let chat = nw_platform::inherited_read_file(chat_handle).map_err(|_| Error::Load)?;
    let embedding = nw_platform::inherited_read_file(embed_handle).map_err(|_| Error::Load)?;
    let mut cpu = Cpu::load_opened(chat, chat_hash, embedding, embed_hash)?;
    let reply = match &command {
        Command::Probe {} => Reply::Ready {},
        Command::Complete {
            messages,
            max_tokens,
            schema,
        } => cpu
            .complete_structured(messages, *max_tokens, *schema)
            .map_or_else(
                |error| Reply::Failed { kind: error.into() },
                |content| Reply::Text { content },
            ),
        Command::Embed { texts } => cpu.embed(texts).map_or_else(
            |error| Reply::Failed { kind: error.into() },
            |values| Reply::Vectors { values },
        ),
    };
    let bytes = encode(reply, OUTPUT_LIMIT)?;
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|_| Error::Inference)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_failure_codes_are_closed_and_cannot_echo_input_or_native_diagnostics() {
        for kind in [FailureKind::Timeout, FailureKind::TooLarge] {
            let bytes = encode(Reply::Failed { kind }, OUTPUT_LIMIT).unwrap();
            let reply: Reply = decode(bytes.as_slice(), OUTPUT_LIMIT).unwrap();
            assert!(matches!(
                reply,
                Reply::Failed {
                    kind: FailureKind::Timeout | FailureKind::TooLarge
                }
            ));
        }
        for body in [
            r#"{"version":1,"lane":"shadow","request_id":1,"body":{"status":"failed","kind":"SYNTHETIC_PRIVATE_FAILURE_62491"}}"#,
            r#"{"version":1,"lane":"shadow","request_id":1,"body":{"status":"failed","kind":"timeout","message":"SYNTHETIC_PRIVATE_FAILURE_62491"}}"#,
            r#"{"version":1,"lane":"shadow","request_id":1,"body":{"status":"failed"}}"#,
        ] {
            let mut frame = (body.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(body.as_bytes());
            assert!(decode::<Reply>(frame.as_slice(), OUTPUT_LIMIT).is_err());
        }
    }
    #[test]
    fn worker_protocol_rejects_wrong_lane_version_extra_frames_and_commands() {
        let valid = encode(Command::Probe {}, MAX_FRAME_BYTES).unwrap();
        assert!(matches!(
            decode::<Command>(valid.as_slice(), MAX_FRAME_BYTES).unwrap(),
            Command::Probe {}
        ));
        for body in [
            r#"{"version":1,"lane":"cover","request_id":1,"body":{"op":"probe"}}"#,
            r#"{"version":65535,"lane":"shadow","request_id":1,"body":{"op":"probe"}}"#,
            r#"{"version":1,"lane":"shadow","request_id":2,"body":{"op":"probe"}}"#,
            r#"{"version":1,"lane":"shadow","request_id":1,"body":{"op":"probe","unexpected":"data"}}"#,
            r#"{"version":1,"lane":"shadow","request_id":1,"body":{"op":"complete","messages":[],"max_tokens":1,"schema":null,"grammar":"execute"}}"#,
        ] {
            let mut frame = (body.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(body.as_bytes());
            assert!(decode::<Command>(frame.as_slice(), MAX_FRAME_BYTES).is_err());
        }
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(decode::<Command>(trailing.as_slice(), MAX_FRAME_BYTES).is_err());
        assert!(decode::<Command>(&[255, 255, 255, 255][..], MAX_FRAME_BYTES).is_err());
        assert!(!valid_vectors(&[vec![f64::MAX]], 1));
    }
}
