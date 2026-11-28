//! CPU llama.cpp backend. There is deliberately no model downloader.
use crate::{Error, Inference};
use llama_cpp_2::{
    context::params::{LlamaContextParams, LlamaPoolingType},
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{LlamaChatMessage, LlamaModel, params::LlamaModelParams},
    sampling::LlamaSampler,
};
use nw_llm::{Message, Role};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    num::NonZeroU32,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

struct EmbeddingTokens(Vec<llama_cpp_2::token::LlamaToken>);
impl Drop for EmbeddingTokens {
    fn drop(&mut self) {
        for token in &mut self.0 {
            token.0.zeroize();
        }
    }
}

pub(crate) fn verified_file(
    path: &Path,
    expected: &str,
) -> Result<(File, std::path::PathBuf), Error> {
    if !path.is_absolute()
        || expected.len() != 64
        || !expected.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Error::Load)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Load);
    }
    let path = path.canonicalize().map_err(|_| Error::Load)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options.open(&path).map_err(|_| Error::Load)?;
    let len = file.metadata().map_err(|_| Error::Load)?.len();
    if !(32..=64 * 1024 * 1024 * 1024).contains(&len) {
        return Err(Error::Load);
    }
    check_hash(&mut file, expected)?;
    Ok((file, path))
}
fn check_hash(file: &mut File, expected: &str) -> Result<(), Error> {
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    if !(32..=64 * 1024 * 1024 * 1024).contains(&file.metadata().map_err(|_| Error::Load)?.len()) {
        return Err(Error::Load);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Load)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| Error::Load)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    if format!("{:x}", h.finalize()) != expected.to_ascii_lowercase() {
        return Err(Error::Hash);
    }
    Ok(())
}
pub struct Cpu {
    chat: LlamaModel,
    embedding: LlamaModel,
    backend: LlamaBackend,
    // Windows read-sharing handles exclude concurrent writes for the models' lifetime.
    _files: [File; 2],
    embedding_sha256: String,
    threads: i32,
}
fn completion_context(trained: u32, input: usize, output: u32) -> Result<u32, Error> {
    let maximum = trained.min(32768);
    let required = input.checked_add(output as usize).ok_or(Error::TooLarge)?;
    if input == 0 || required > maximum as usize {
        return Err(Error::TooLarge);
    }
    // A fresh request needs only its own KV cache. Never reserve the entire training window.
    Ok((required.div_ceil(512) * 512)
        .max(512)
        .min(maximum as usize) as u32)
}
impl Cpu {
    pub fn load(
        chat: &Path,
        chat_hash: &str,
        embedding: &Path,
        embedding_hash: &str,
    ) -> Result<Self, Error> {
        #[cfg(windows)]
        {
            let (chat, _) = verified_file(chat, chat_hash)?;
            let (embedding, _) = verified_file(embedding, embedding_hash)?;
            Self::load_opened(chat, chat_hash, embedding, embedding_hash)
        }
        #[cfg(not(windows))]
        Self::load_paths(chat, chat_hash, embedding, embedding_hash)
    }
    #[cfg(not(windows))]
    fn load_paths(
        chat: &Path,
        chat_hash: &str,
        embedding: &Path,
        embedding_hash: &str,
    ) -> Result<Self, Error> {
        llama_cpp_2::send_logs_to_tracing(
            llama_cpp_2::LogOptions::default().with_logs_enabled(false),
        );
        let (mut chat_file, _chat_path) = verified_file(chat, chat_hash)?;
        let (mut embedding_file, _embedding_path) = verified_file(embedding, embedding_hash)?;
        let backend = LlamaBackend::init().map_err(|_| Error::Load)?;
        let params = LlamaModelParams::default()
            .with_n_gpu_layers(0)
            .with_use_mmap(false);
        let chat =
            LlamaModel::load_from_file(&backend, _chat_path, &params).map_err(|_| Error::Load)?;
        let embedding = LlamaModel::load_from_file(&backend, _embedding_path, &params)
            .map_err(|_| Error::Load)?;
        check_hash(&mut chat_file, chat_hash)?;
        check_hash(&mut embedding_file, embedding_hash)?;
        chat.chat_template(None).map_err(|_| Error::Load)?;
        let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(8)) as i32;
        Ok(Self {
            chat,
            embedding,
            backend,
            _files: [chat_file, embedding_file],
            embedding_sha256: embedding_hash.to_ascii_lowercase(),
            threads,
        })
    }
    #[cfg(windows)]
    pub fn load_opened(
        mut chat_file: File,
        chat_hash: &str,
        mut embedding_file: File,
        embedding_hash: &str,
    ) -> Result<Self, Error> {
        check_hash(&mut chat_file, chat_hash)?;
        check_hash(&mut embedding_file, embedding_hash)?;
        llama_cpp_2::send_logs_to_tracing(
            llama_cpp_2::LogOptions::default().with_logs_enabled(false),
        );
        let backend = LlamaBackend::init().map_err(|_| Error::Load)?;
        let params = LlamaModelParams::default()
            .with_n_gpu_layers(0)
            .with_use_mmap(false);
        let chat = LlamaModel::load_from_open_file(&backend, &mut chat_file, &params)
            .map_err(|_| Error::Load)?;
        let embedding = LlamaModel::load_from_open_file(&backend, &mut embedding_file, &params)
            .map_err(|_| Error::Load)?;
        check_hash(&mut chat_file, chat_hash)?;
        check_hash(&mut embedding_file, embedding_hash)?;
        chat.chat_template(None).map_err(|_| Error::Load)?;
        let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(8)) as i32;
        Ok(Self {
            chat,
            embedding,
            backend,
            _files: [chat_file, embedding_file],
            embedding_sha256: embedding_hash.to_ascii_lowercase(),
            threads,
        })
    }
    fn params(&self, context: u32) -> LlamaContextParams {
        LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(context))
            .with_n_batch(512)
            .with_n_ubatch(512)
            .with_n_threads(self.threads)
            .with_n_threads_batch(self.threads)
    }
}
impl Inference for Cpu {
    fn embedding_sha256(&self) -> Option<&str> {
        Some(&self.embedding_sha256)
    }
    fn embedding_recipe(&self) -> Option<&str> {
        nw_llm::embedding::for_model(&self.embedding_sha256).map(|recipe| recipe.id)
    }
    fn complete(&mut self, messages: &[Message], max_tokens: u32) -> Result<String, Error> {
        self.complete_structured(messages, max_tokens, None)
    }
    fn complete_structured(
        &mut self,
        messages: &[Message],
        max_tokens: u32,
        schema: Option<nw_llm::OutputSchema>,
    ) -> Result<String, Error> {
        let seconds = if matches!(
            schema,
            Some(nw_llm::OutputSchema::LinkageV1 | nw_llm::OutputSchema::LinkageFactsV1)
        ) {
            200
        } else {
            110
        };
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let template = self.chat.chat_template(None).map_err(|_| Error::Load)?;
        let chat = messages
            .iter()
            .map(|m| {
                LlamaChatMessage::new(
                    match m.role {
                        Role::System => "system",
                        Role::User => "user",
                        Role::Assistant => "assistant",
                    }
                    .into(),
                    m.content.clone(),
                )
                .map_err(|_| Error::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prompt = Zeroizing::new(
            self.chat
                .apply_chat_template(&template, &chat, true)
                .map_err(|_| Error::Invalid)?,
        );
        let tokens = self.chat.vocab().tokenize(prompt.as_bytes(), true, true);
        let context = completion_context(self.chat.n_ctx_train(), tokens.len(), max_tokens)?;
        let mut ctx = self
            .chat
            .new_context(&self.backend, self.params(context))
            .map_err(|_| Error::Inference)?;
        let mut batch = LlamaBatch::new(512, 1);
        for (start, chunk) in tokens.chunks(512).enumerate() {
            if Instant::now() > deadline {
                return Err(Error::Timeout);
            }
            batch.clear();
            for (i, token) in chunk.iter().enumerate() {
                let pos = start * 512 + i;
                batch
                    .add(*token, pos as i32, &[0], pos == tokens.len() - 1)
                    .map_err(|_| Error::Inference)?;
            }
            ctx.decode(&mut batch).map_err(|_| Error::Inference)?;
        }
        let mut sampler = if let Some(schema) = schema {
            let grammar = match schema {
                nw_llm::OutputSchema::PrivacyV1 => include_str!("privacy.gbnf"),
                nw_llm::OutputSchema::LinkageV1 => include_str!("linkage.gbnf"),
                nw_llm::OutputSchema::LinkageFactsV1 => include_str!("linkage-facts.gbnf"),
                nw_llm::OutputSchema::PlanV1 => include_str!("plan.gbnf"),
            };
            LlamaSampler::chain_simple([
                LlamaSampler::grammar(&self.chat, grammar, "root").map_err(|_| Error::Inference)?,
                LlamaSampler::greedy(),
            ])
        } else {
            LlamaSampler::greedy()
        };
        let mut generated = Vec::new();
        for pos in (tokens.len() as i32..).take(max_tokens as usize) {
            if Instant::now() > deadline {
                return Err(Error::Timeout);
            }
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            // llama-cpp-2 0.1.161 sample() already accepts the token. Accepting twice
            // corrupts stateful grammar samplers and can throw across the native boundary.
            if self.chat.vocab().is_eog(token) {
                break;
            }
            generated.push(token);
            // Token pieces can be incomplete UTF-8; decode once after generation.
            if generated.len() % 64 == 0
                && self.chat.vocab().detokenize(&generated, false, false).len()
                    > nw_proto::MAX_TEXT_BYTES
            {
                return Err(Error::TooLarge);
            }
            batch.clear();
            batch
                .add(token, pos, &[0], true)
                .map_err(|_| Error::Inference)?;
            ctx.decode(&mut batch).map_err(|_| Error::Inference)?;
        }
        let bytes = Zeroizing::new(self.chat.vocab().detokenize(&generated, false, false));
        let answer = String::from_utf8(bytes.to_vec()).map_err(|_| Error::Inference)?;
        if answer.len() > nw_proto::MAX_TEXT_BYTES || answer.trim().is_empty() {
            return Err(Error::Inference);
        }
        Ok(answer)
    }
    fn embed(&mut self, texts: &[String]) -> Result<Vec<Vec<f64>>, Error> {
        let deadline = Instant::now() + Duration::from_secs(110);
        let recipe = nw_llm::embedding::for_model(&self.embedding_sha256).ok_or(Error::Invalid)?;
        let limit = self.embedding.n_ctx_train().min(recipe.max_tokens);
        let mut sequences = Vec::with_capacity(texts.len());
        for text in texts {
            let input = Zeroizing::new(format!("{}{text}", recipe.prefix));
            let tokens = EmbeddingTokens(self.embedding.vocab().tokenize(
                input.as_bytes(),
                true,
                true,
            ));
            if tokens.0.is_empty() || tokens.0.len() > limit as usize {
                return Err(Error::TooLarge);
            }
            sequences.push(tokens);
        }
        let longest = sequences
            .iter()
            .map(|tokens| tokens.0.len())
            .max()
            .ok_or(Error::Invalid)?;
        let context = match recipe.pooling {
            // Preserve the existing Nomic representation, including its fixed
            // context/rotary parameters. Qwen's cache can fit the actual input.
            nw_llm::embedding::Pooling::Mean => limit,
            nw_llm::embedding::Pooling::Last => completion_context(limit, longest, 0)?,
        };
        let params = self
            .params(context)
            .with_n_batch(context)
            .with_n_ubatch(context)
            .with_embeddings(true)
            .with_pooling_type(match recipe.pooling {
                nw_llm::embedding::Pooling::Mean => LlamaPoolingType::Mean,
                nw_llm::embedding::Pooling::Last => LlamaPoolingType::Last,
            });
        let mut ctx = self
            .embedding
            .new_context(&self.backend, params)
            .map_err(|_| Error::Inference)?;
        let mut batch = LlamaBatch::new(context as usize, 1);
        let mut output = vec![];
        for tokens in sequences {
            if Instant::now() > deadline {
                return Err(Error::Timeout);
            }
            ctx.clear_kv_cache();
            batch.clear();
            batch
                .add_sequence(&tokens.0, 0, false)
                .map_err(|_| Error::Inference)?;
            ctx.decode(&mut batch).map_err(|_| Error::Inference)?;
            let vector = ctx.embeddings_seq_ith(0).map_err(|_| Error::Inference)?;
            if vector.len() != recipe.dimension {
                return Err(Error::Inference);
            }
            let norm = vector
                .iter()
                .map(|v| f64::from(*v).powi(2))
                .sum::<f64>()
                .sqrt();
            if !norm.is_finite() || norm < 1e-12 {
                return Err(Error::Inference);
            }
            output.push(vector.iter().map(|v| f64::from(*v) / norm).collect());
        }
        Ok(output)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_completion_cache_fits_actual_tokens_without_exceeding_training_limit() {
        assert_eq!(completion_context(32768, 400, 1024).unwrap(), 1536);
        assert_eq!(completion_context(1400, 400, 1000).unwrap(), 1400);
        assert_eq!(completion_context(65536, 32000, 768).unwrap(), 32768);
        assert!(completion_context(1400, 401, 1000).is_err());
        assert!(completion_context(32768, usize::MAX, 1).is_err());
        assert!(completion_context(32768, 0, 1).is_err());
        assert_eq!(completion_context(32768, 9001, 0).unwrap(), 9216);
        assert!(completion_context(8192, 8193, 0).is_err());
    }
    #[test]
    fn model_hash_is_checked_before_native_parser() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.gguf");
        std::fs::write(&path, [17u8; 64]).unwrap();
        assert!(matches!(
            verified_file(&path, &"0".repeat(64)),
            Err(Error::Hash)
        ));
        let hash = format!("{:x}", Sha256::digest([17u8; 64]));
        assert!(verified_file(&path, &hash).is_ok());
    }
}
